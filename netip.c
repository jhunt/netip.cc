#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <arpa/inet.h>
#include <getopt.h>

#define VERSION "1.0"

#define DGRAM_MAX_SIZE    512
#define DGRAM_HEADER_SIZE 12

#define F_REPLY    0x8000
#define F_AA       0x0400
#define F_NXDOMAIN 0x0003
#define F_REFUSED  0x0005

#define REPLY_REFUSED  (F_REPLY |        F_REFUSED)
#define REPLY_NXDOMAIN (F_REPLY | F_AA | F_NXDOMAIN)

typedef uint32_t ipv4_t;

typedef struct {
	/* header */
	uint16_t id;
	uint16_t flags;
	uint16_t qd_count;
	uint16_t an_count;
	uint16_t ns_count;
	uint16_t ar_count;

	char     dgram[DGRAM_MAX_SIZE];
	ssize_t  dlen;
	char    *dend;
} msg_t;

#define QR(h)      (((h).flags)&0x8000)
#define OPCODE(h) ((((h).flags)&0x7000) >> 12)
#define AA(h)      (((h).flags)&0x0400)
#define TC(h)      (((h).flags)&0x0200)
#define RD(h)      (((h).flags)&0x0100)
#define RA(h)      (((h).flags)&0x0080)
#define RCODE(h)   (((h).flags)&0x000f)

#define errorf(...) fprintf(stderr, __VA_ARGS__)
#ifdef NETIP_DEBUG
#  define debugf(...) fprintf(stderr, __VA_ARGS__)
#  define hexdump(io,b,l) ({\
	size_t ____n; \
	for (____n = 0; ____n < (l); ____n++) { \
		if (____n && ____n % 16 == 0) \
			fprintf((io), "\n"); \
		fprintf((io), (____n > 12 && isprint((b)[____n]) ? " %c " : "%02x "), (unsigned char)(b)[____n]); \
	} \
	fprintf((io), "\n"); \
})
#  define pktdump(io,m) ({\
	fprintf((io), ">> %d %08x\n", ntohs((m)->id), (m)->flags); \
	fprintf((io), ">> flags [%s %s %s %s %s]\n", \
		(QR(msg) ? "QR" : "-"), (AA(msg) ? "AA" : "-"), \
		(TC(msg) ? "TC" : "-"), (RD(msg) ? "RD" : "-"), \
		(RA(msg) ? "RA" : "-")); \
	fprintf((io), ">> opcode %d\n", OPCODE(msg)); \
	fprintf((io), ">> rcode  %d\n", RCODE(msg)); \
	fprintf((io), ">> rr: %d QD, %d AN, %d NS, %d AR\n", \
		ntohs((m)->qd_count), ntohs((m)->an_count), \
		ntohs((m)->ns_count), ntohs((m)->ar_count)); \
})
#else
#  define debugf(...)
#  define hexdump(io,b,l)
#  define pktdump(io,m)
#endif

#define reply(m,f) ({\
	(m)->flags = htons((f)); \
	(m)->qd_count = 0; \
	(m)->an_count = 0; \
	(m)->ns_count = 0; \
	(m)->ar_count = 0; \
	(m)->dlen = DGRAM_HEADER_SIZE; \
	memcpy((m)->dgram, (m), DGRAM_HEADER_SIZE); \
})

static char *
extract_name(msg_t *h, char **rest)
{
	char *name;
	size_t n, i, l;

	for (n = 0, i = DGRAM_HEADER_SIZE; i < h->dlen; ) {
		if ((h->dgram[i] & 0xc0) == 0xc0) {
			/* don't understand compression yet; bail */
			return NULL;
		}

		if (h->dgram[i] == '\0') {
			break;
		}

		l = h->dgram[i];
		if (l > h->dlen) {
			/* Whoa, that's some major corruption */
			return NULL;
		}
		n += l + 1;
		i += l + 1;
	}

	if (n == 0) {
		/* don't support zero-length QNAMEs... */
		return NULL;
	}

	debugf("name should be %li octets long\n", n);
	name = calloc(n, sizeof(char));
	if (!name) {
		errorf("failed to allocate buffer for name extraction: %s (error %d)\n",
				strerror(errno), errno);
		return NULL;
	}
	memset(name, '.', n - 1);

	for (n = 0, i = DGRAM_HEADER_SIZE; i < h->dlen; ) {
		if (h->dgram[i] == '\0') {
			break;
		}

		l = h->dgram[i];
		memcpy(name + n, &h->dgram[0] + i + 1, l);
		n += l + 1;
		i += l + 1;
	}
	if (rest) {
		*rest = &h->dgram[0] + i + 1;
	}
	return name;
}

static int
ipv4quad(const char *s)
{
	long q;
	char *end = NULL;

	q = strtol(s, &end, 10);
	if ((end && *end) || q < 0 || q > 255)
		return -1;
	return (int)q;
}

static ipv4_t
extract_ip(char *name, const char *base)
{
	size_t namelen, baselen, n;
	char *a, *b;
	union {
		uint8_t q[4];
		ipv4_t  v;
	} ip;
	int quad;

	namelen = strlen((const char *)name);
	baselen = strlen((const char *)base);
	if (namelen < baselen) {
		/* `name' is too short to end with `base' */
		return 0;
	}

	if (memcmp(name + namelen - baselen, base, baselen) != 0) {
		/* `name' does not end with `base' */
		return 0;
	}

	/* work backwards, finding each [a..b] that describes
	   an octet, until we find all 4 */
	n = 0;
	b = name + namelen - baselen - 1;
	*b = '\0';
	for (;;) {
		a = strrchr(name, '.');
		if (a) b = a + 1;
		else   a = b = name;

		quad = ipv4quad(b);
		if (quad < 0) {
			/* `name' does not contain a valid IPv4 dotted-quad address. */
			debugf("quad '%s' is bad\n", b);
			return 0;
		}
		ip.q[n++] = quad;
		if (n >= 4) break;
		if (a == name) break;

		*a = '\0';
	}

	return ip.v;
}

static int
listen_on(const char *host, int port)
{
	int rc, fd, val;
	struct sockaddr_in ipv4;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		errorf("failed to create a socket: %s (error %d)\n",
			strerror(errno), errno);
		return -1;
	}

	val = 1;
	rc = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));
	if (rc != 0) {
		errorf("unable to set SO_REUSEADDR on listening socket: %s (error %d)\n",
			strerror(errno), errno);
		/* no point in failing; just keep going */
	}

	ipv4.sin_family = AF_INET;
	ipv4.sin_port   = htons(port);
	rc = inet_pton(ipv4.sin_family, host, &ipv4.sin_addr);
	if (rc != 1) {
		errorf("unable to parse bind address %s:%d: %s (error %d)\n",
			host, port, strerror(errno), errno);
		close(fd);
		return -1;
	}

	rc = bind(fd, (struct sockaddr*)&ipv4, sizeof(ipv4));
	if (rc != 0) {
		errorf("unable to bind listening socket: %s (error %d)\n",
			strerror(errno), errno);
		close(fd);
		return -1;
	}

	return fd;
}

static int
parseaddr(const char *addr, char **host, int *port)
{
	char *p, *end;
	long _port;

	*host = strdup(addr);
	p = strchr(*host, ':');
	if (!p) {
		*port = 53;
		return 0;
	}

	*p++ = '\0';
	if (!p) {
		/* invalid 'host:' format (no port, colon present) */
		return -1;
	}

	_port = strtol(p, &end, 10);
	if ((end && *end) || _port < 1 || _port > 65535) {
		return -1;
	}
	*port = _port;
	return 0;
}

static int DO_SHUTDOWN = 0;
void trigger_shutdown(int sig)
{
	DO_SHUTDOWN = 1;
}

static int
install_signal_handlers()
{
	struct sigaction sa, old;
	int rc;

	sa.sa_flags = 0; /* specifically, clear SA_RESTART */
	sa.sa_handler = trigger_shutdown;

	rc = sigaction(SIGTERM, &sa, &old);
	if (rc != 0) return -1;

	rc = sigaction(SIGINT, &sa, &old);
	if (rc != 0) return -1;

	return 0;
}

#ifdef FUZZ
#  define NEXT return 1
#else
#  define NEXT continue
#endif

int main(int argc, char **argv)
{
	int rc;

	int fd;
	struct sockaddr_in peer;
	socklen_t len;
	char peer_ip[INET6_ADDRSTRLEN];

	ssize_t n;
	msg_t msg;

	char *name, *rest;
	uint16_t qtype, qclass, v;
	ipv4_t ip;

	char *host, *domain;
	int port;

	struct option long_opts[] = {
		{ "help",       no_argument, 0, 'h' },
		{ "bind", required_argument, 0, 'b' },
		{ "name", required_argument, 0, 'n' },
		{ 0, 0, 0, 0 },
	};

	/* parse options */
	domain = strdup("netip.cc");
	host = strdup("127.0.0.1");
	port = 53;
	for (;;) {
		int c = getopt_long(argc, argv, "hb:n:", long_opts, NULL);
		if (c == -1) break;

		switch (c) {
		case '?':
		case 'h':
			printf("netip v" VERSION " - a fast, echo-response DNS server\n"
			       "Copyright (C) James Hunt <james@niftylogic.com>\n"
			       "\n"
			       "USAGE: %s [-b host:port] [-n base.tld]\n"
			       "\n"
			       "OPTIONS:\n"
			       "\n"
			       "  -h, --help    Show the help screen\n"
			       "  -b, --bind    Host IP address and port to bind (UDP)\n"
			       "                (defaults to 127.0.0.1:53)\n"
			       "  -n, --name    Toplevel domain to resolve for\n"
			       "                (defaults to netip.cc)\n"
			       "\n"
			       "netip does not daemonize; if you want to run it in the\n"
			       "background, you will need to arrange something yourself.\n"
			       "\n"
			       "Error and warning messages will be printed to standard\n"
			       "error; statistics will go to standard output.\n"
			       "\n", argv[0]);
			return 0;

		case 'b':
			free(host);
			rc = parseaddr(optarg, &host, &port);
			if (rc != 0) {
				errorf("invalid --bind address '%s'\n", optarg);
				return 1;
			}
			break;

		case 'n':
			free(domain);
			domain = strdup(optarg);
		}
	}
	rc = install_signal_handlers();
	if (rc != 0) {
		errorf("failed to install signal handlers: %s (error %d)\n",
			strerror(errno), errno);
		return 1;
	}

#ifdef FUZZ
	fd = fileno(stdin);
#else
	fd = listen_on(host, port);
	if (fd < 0) {
		return 1;
	}
#endif

	for (;;) {
#ifndef FUZZ
		len = sizeof(peer);
		debugf("waiting to receive up to %d bytes on fd %d\n", DGRAM_MAX_SIZE, fd);
		msg.dlen = recvfrom(fd, msg.dgram, DGRAM_MAX_SIZE,
			MSG_WAITALL, (struct sockaddr*)&peer, &len);
		if (msg.dlen < 0) {
			if (DO_SHUTDOWN) break;
			errorf("failed to recvfrom() client: %s (error %d)\n",
				strerror(errno), errno);
			NEXT;
		}

		if (inet_ntop(AF_INET, &peer.sin_addr.s_addr, peer_ip, INET6_ADDRSTRLEN)) {
			debugf("received query from %s:%d\n", peer_ip, ntohs(peer.sin_port));
		} else {
			errorf("received query from unknown client (%s, error %d)\n",
				strerror(errno), errno);
		}
#else
		msg.dlen = read(fd, msg.dgram, DGRAM_MAX_SIZE);
		if (msg.dlen < 0) {
			if (DO_SHUTDOWN) break;
			errorf("failed to read from fd %d: %s (error %d)\n",
				fd, strerror(errno), errno);
			NEXT;
		}
#endif

		hexdump(stderr, msg.dgram, msg.dlen);

		if (msg.dlen < DGRAM_HEADER_SIZE) {
			debugf("short packet of %li octets received; ignoring\n", msg.dlen);
			NEXT;
		}
		msg.dend = &msg.dgram[0] + msg.dlen;
		memcpy(&msg, msg.dgram, DGRAM_HEADER_SIZE);
		msg.flags = ntohs(msg.flags);

		pktdump(stderr, &msg);

		if (QR(msg) || AA(msg) || TC(msg) || RA(msg) || OPCODE(msg)
		 || msg.an_count || msg.ns_count || msg.ar_count) {
			debugf("malformed query packet; refusing\n");
			reply(&msg, REPLY_REFUSED);
			goto reply;
		}
		if (ntohs(msg.qd_count) != 1) {
			debugf("malformed query packet (QD_COUNT != 1); refusing\n");
			reply(&msg, REPLY_REFUSED);
			goto reply;
		}

		name = extract_name(&msg, &rest);
		if (name == NULL) {
			debugf("unable to extract QNAME; refusing\n");
			reply(&msg, REPLY_REFUSED);
			goto reply;
		}
		if (rest + 3 > msg.dend) {
			debugf("malformed query packet; refusing\n");
			reply(&msg, REPLY_REFUSED);
			goto reply;
		}
		memcpy(&qtype,  rest,     sizeof(qtype));  qtype  = ntohs(qtype);
		memcpy(&qclass, rest + 2, sizeof(qclass)); qclass = ntohs(qclass);
		if (qtype != 0x01 || qclass != 0x01) {
			debugf("query is not for IN A; refusing\n");
			reply(&msg, REPLY_REFUSED);
			goto reply;
		}

		debugf("looking up '%s'\n", name);
		/* extract the IP given the basename ".netip.cc" */
		ip = extract_ip(name, domain);
		if (ip == 0 || ip == 0xffffffff) {
			debugf("invalid domain %s; replying NXDOMAIN\n", name);
			reply(&msg, REPLY_NXDOMAIN);
			goto reply;
		}
		debugf("ip: %04x\n", ip);

		/* respond */
		msg.flags = htons(0x8000   /* QR = 1 */
		                | 0x0400); /* AA = 1 */
		msg.qd_count = 0;
		msg.an_count = htons(1);
		msg.ns_count = 0;
		msg.ar_count = 0;
		if (DGRAM_MAX_SIZE - msg.dlen < 10) {
			/* need at least 11 _more_ octets for the IN A response */
			debugf("query is too large to respond to; ignoring\n");
			NEXT;
		}

		memcpy(msg.dgram, &msg, DGRAM_HEADER_SIZE);

		memset(msg.dgram + msg.dlen, 0, 4);            /* TTL       0     */
		msg.dlen += 4;

		v = htons(sizeof(ip)); /* length of an IPv4 32-bit address */
		memcpy(msg.dgram + msg.dlen, &v, sizeof(v));   /* RDLENGTH  4     */
		msg.dlen += sizeof(v);

		ip = htonl(ip);
		memcpy(msg.dgram + msg.dlen, &ip, sizeof(ip)); /* RDATA     (ip)  */
		msg.dlen += sizeof(ip);

		hexdump(stderr, msg.dgram, msg.dlen);

reply:
#ifndef FUZZ
		debugf("replying in %li bytes on fd %d\n", msg.dlen, fd);
		n = sendto(fd, msg.dgram, msg.dlen, 0, (struct sockaddr*)&peer, len);
		if (n < 0) {
			if (DO_SHUTDOWN) break;
			debugf("failed sending response: %s (error %d)\n",
				strerror(errno), errno);
			NEXT;
		}
		if (n != msg.dlen) {
			debugf("short write (only %li/%li bytes written)!\n", n, msg.dlen);
			NEXT;
		}
#endif

		NEXT;
	}

	close(fd);
	return 0;
}
