#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <getopt.h>
#include <time.h>

#ifndef VERSION
#define VERSION "(dev)"
#endif

#define MICROSECONDS 1000000

#define DGRAM_MAX_SIZE    512
#define DGRAM_HEADER_SIZE 12

#define F_REPLY    0x8000
#define F_AA       0x0400
#define F_NOERROR  0x0000
#define F_NXDOMAIN 0x0003
#define F_REFUSED  0x0005

#define REPLY_REFUSED  (F_REPLY |        F_REFUSED)
#define REPLY_NXDOMAIN (F_REPLY | F_AA | F_NXDOMAIN)

#define Q_IN      0x01

#define Q_A       0x01
#define Q_AAAA    0x1c
#define Q_NS      0x02
#define Q_SOA     0x06

#define Q_IN_A    0x0101
#define Q_IN_AAAA 0x011c
#define Q_IN_NS   0x0102
#define Q_IN_SOA  0x0106

#define BADIP   ((ipv4_t)(0xffffff))

#define Q(c,t) (((c) << 8) | (t))

#define OFFSET(c) ((unsigned char)(c))

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

static uint32_t SERIAL = 0;
static uint32_t TTL    = 300;

typedef uint32_t ipv4_t;

typedef struct {
	ssize_t len;
	char    data[];
} name_t;

static name_t* name_parse(const char *s);
static name_t* name_extract(const char *b, size_t max);
static char*   name_string(name_t *name);
static int     name_is(name_t *name, const char *label, name_t *domain);
static ssize_t name_search(name_t *haystack, name_t *needle);
static ipv4_t  name_ip(name_t *query, name_t *tld);

typedef struct {
	/* header */
	uint16_t id;
	uint16_t flags;
	uint16_t qd_count;
	uint16_t an_count;
	uint16_t ns_count;
	uint16_t ar_count;

	ssize_t  len;
	char     data[DGRAM_MAX_SIZE];
	char    *dend;
} msg_t;

/*********************************************************************/

static name_t *
name_parse(const char *s)
{
	size_t len;
	char *p, c;

	len = strlen(s);
	name_t *name = calloc(1, sizeof(name_t) + 1 + len + 1);
	if (!name)
		return NULL;

	name->len = 1 + len + 1;
	memcpy(name->data + 1, s, len);
	name->data[0] = '.';

	for (c = 0, p = name->data + len; p >= name->data; p--, c++) {
		if (*p == '.') { *p-- = c; c = 0; }
	}

	return name;
}

static name_t *
name_extract(const char *b, size_t max)
{
	size_t i, n;
	name_t *name;

	n = i = 0;
	while (i < max && b[i]) {
		n += 1 + OFFSET(b[i]);
		i += 1 + OFFSET(b[i]);
		if (i > max)
			return NULL;
	}

	name = calloc(1, sizeof(name_t) + n + 1);
	if (!name)
		return NULL;

	name->len = n + 1;
	memcpy(name->data, b, n);
	return name;
}

static char *
name_string(name_t *name)
{
	size_t i;
	char *s;

	s = calloc(1, name->len);
	if (!s)
		return NULL;

	memcpy(s, name->data + 1, name->len - 1);
	for (i = OFFSET(name->data[0]); i < name->len && OFFSET(name->data[i+1]); i += OFFSET(name->data[i+1])+1)
		s[i] = '.';
	return s;
}

static int
name_eq(name_t *a, name_t *b)
{
	return a->len == b->len
	    && memcmp(a, b, a->len) == 0;
}

static int
name_is(name_t *name, const char *label, name_t *domain)
{
	ssize_t off;

	off = name_search(name, domain);
	if (off < 0                                  /* name doesn't end in domain */
	 || OFFSET(name->data[0]) != strlen(label)   /* 1st label is too long      */
	 || OFFSET(name->data[0]) != off - 1         /* more than one prefix label */
	 || memcmp(name->data + 1, label, OFFSET(name->data[0])) != 0)
		return 0;

	return 1; /* true */
}

static ssize_t
name_search(name_t *haystack, name_t *needle)
{
	size_t i;
	ssize_t n;

	i = 0;
	n = haystack->len;
	while (n >= needle->len) {
		if (memcmp(haystack->data + i, needle->data, needle->len) == 0)
			return i;
		n -= OFFSET(haystack->data[i]) + 1;
		i += OFFSET(haystack->data[i]) + 1;
	}
	return -1;
}

static ipv4_t
name_ip(name_t *query, name_t *tld)
{
	size_t i, a, n;
	ssize_t end;
	ipv4_t ip;
	int octet;

	end = name_search(query, tld);
	if (end < 0)
		return BADIP;

	a = i = n = 0;
	while (i < end) {
		i += OFFSET(query->data[i]) + 1;
		if (n++ >= 4) {
			a += OFFSET(query->data[a]) + 1;
		}
	}

	ip = 0;
	for (n = 0; n < 4 && OFFSET(query->data[a]); n++, a += OFFSET(query->data[a]) + 1) {
		octet = 0;
		for (i = 0; i < OFFSET(query->data[a]); i++) {
			if (!isdigit(query->data[a + 1 + i]))
				return BADIP;
			octet = octet * 10 + query->data[a + 1 + i] - '0';
		}
		if (octet > 255)
			return BADIP;
		ip = ip << 8 | octet;
	}
	if (ip == 0xffffffff)
		return BADIP;

	return htonl(ip);
}

/*********************************************************************/

static inline char *
msgins(msg_t *b) { return b->data + b->len; }

static inline size_t
msgleft(msg_t *b) { return DGRAM_MAX_SIZE - b->len; }

static inline size_t
min(size_t a, size_t b) { return a > b ? b : a; }

static inline void
msgcpy(msg_t *dst, const void *src, size_t n)
{
	n = min(msgleft(dst), n);
	memcpy(msgins(dst), src, n);
	dst->len += n;
}

static inline void msg8 (msg_t *dst, uint8_t  v) { msgcpy(dst, &v, sizeof(v)); }
static inline void msg16(msg_t *dst, uint16_t v) { msgcpy(dst, &v, sizeof(v)); }
static inline void msg32(msg_t *dst, uint32_t v) { msgcpy(dst, &v, sizeof(v)); }

static inline void
msgref(msg_t *m, size_t off) { msg16(m, htons(0xc000 | (DGRAM_HEADER_SIZE + off))); }

static inline void
msglabel(msg_t *m, const char *name)
{
	size_t n;
	char *dst;

	dst = msgins(m);
	n = strlen(name);
	*dst++ = n;
	memcpy(dst, name, n);
	m->len += 1 + n;
}

#define QR(h)      (((h).flags)&0x8000)
#define OPCODE(h) ((((h).flags)&0x7000) >> 12)
#define AA(h)      (((h).flags)&0x0400)
#define TC(h)      (((h).flags)&0x0200)
#define RD(h)      (((h).flags)&0x0100)
#define RA(h)      (((h).flags)&0x0080)
#define RCODE(h)   (((h).flags)&0x000f)

static inline void
reply(msg_t *m, uint16_t f)
{
	m->flags = htons(f);
	m->qd_count = m->an_count = 0;
	m->ns_count = m->ar_count = 0;
	m->len = DGRAM_HEADER_SIZE;
	memcpy(m->data, m, DGRAM_HEADER_SIZE);
}

static const char *
qclass_name(uint16_t c)
{
	static const char *known[] = { NULL,
		"IN",
	};
	static int n = 1;

	if (c < 1 || c > n) {
		return "(unknown)";
	}
	return known[c];
}

static const char *
qtype_name(uint16_t t)
{
	static const char *known[] = { NULL,
		"A",
		"NS",
		"MD",
		"MF",
		"CNAME",
		"SOA",
		"MB",
		"MG",
		"MR",
		"NULL",
		"WKS",
		"PTR",
		"HINFO",
		"MINFO",
		"MX",
		"TXT",
	};
	static int n = 16;

	if (t < 1 || t > n) {
		return "(unknown)";
	}
	return known[t];
}

static int
is_soa(const char *name, const char *base)
{
	size_t namelen, baselen, n;

	namelen = strlen(name);
	baselen = strlen(base);
	if (namelen >= baselen
	 && memcmp(name + namelen - baselen, base, baselen) == 0) {
		return 1;
	}
	return 0;
}

static int
is_ns(const char *name, const char *base)
{
	size_t namelen, baselen, n;

	namelen = strlen(name);
	baselen = strlen(base);
	if (namelen == baselen + 4
	 && name[0] == 'n' && name[1] == 's' && isdigit(name[2]) && name[3] == '.'
	 && memcmp(name + namelen - baselen, base, baselen) == 0) {
		return 1;
	}
	return 0;
}

static ipv4_t
ip_parse(const char *ip)
{
	struct sockaddr_in ipv4;

	if (!ip || !*ip) {
		ip = "127.0.0.1";
	}
	if (!inet_pton(AF_INET, ip, &ipv4.sin_addr.s_addr)) {
		return 0;
	}
	return ipv4.sin_addr.s_addr;
}

static uint32_t
serial_parse(const char *s)
{
	long q;
	char *end = NULL;

	if (*s == '-' && !*(s+1)) {
		time_t t = time(NULL);
		return t < 0 ? 0 : t;
	}

	q = strtol(s, &end, 10);
	return (end && *end) || q < 0 ? 0 : q;
}

static int
listen_on(ipv4_t ip, int port)
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

	ipv4.sin_family      = AF_INET;
	ipv4.sin_port        = htons(port);
	ipv4.sin_addr.s_addr = ip;

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
bind_parse(const char *addr, ipv4_t *ip, int *port)
{
	char *p, *end, *host;
	long _port;

	errno = EINVAL;
	*port = 53;

	host = strdup(addr);
	p = strchr(host, ':');
	if (p) {
		*p++ = '\0';
		if (!p) {
			/* invalid 'host:' format (no port, colon present) */
			free(host);
			return -1;
		}

		_port = strtol(p, &end, 10);
		if ((end && *end) || _port < 1 || _port > 65535) {
			free(host);
			return -1;
		}
		*port = _port;
	}

	*ip = ip_parse(host);
	free(host);
	return *ip && *ip != 0xffffffff ? 0 : -1;
}

static size_t
namecpy(unsigned char *dst, const char *src)
{
	size_t n;
	unsigned char *p, *end, c;

	n = strlen(src);
	memcpy(dst + 1, src, n);
	*dst = '.';

	for (c = 0, p = dst + n; p >= dst; p--, c++) {
		if (*p == '.') {
			*p-- = c;
			c = 0;
		}
	}

	return 1 + n;
}

static void
msg_prep_reply(msg_t *m, uint16_t f)
{
	m->flags = htons(F_REPLY | f);
	m->qd_count = htons(1);
	m->an_count = m->ns_count = m->ar_count = 0;
	for (m->len = DGRAM_HEADER_SIZE; OFFSET(m->data[m->len]) != 0; m->len++)
		;
	m->len += 5; /* 00 [qclass] [qtype] */
}

static inline void
msg_commit(msg_t *m)
{
	memcpy(m->data, m, DGRAM_HEADER_SIZE);
}

#define namelen(s) (1 + strlen(s))

static int
reply_soa(msg_t *m, name_t *query, name_t *tld, int ns)
{
	ssize_t off;
	uint16_t rdlength;
	uint32_t serial = htonl(SERIAL);
	uint32_t ttl    = htonl(TTL);

	off = name_search(query, tld);
	if (off < 0) {
		debugf("did not find base domain as suffix of query; refusing\n");
		reply(m, REPLY_REFUSED);
		return 0;
	}

	msg_prep_reply(m, F_AA);
	if (ns) {
		m->ns_count = htons(1);
	} else {
		m->an_count = htons(1);
	}
	msg_commit(m);

	rdlength = namelen("ns1")        + 2     /* MNAME   */
	         + namelen("hostmaster") + 2     /* RNAME   */
	         + sizeof(serial)                /* SERIAL  */
	         + sizeof(ttl)                   /* REFRESH */
	         + sizeof(ttl)                   /* RETRY   */
	         + sizeof(ttl)                   /* EXPIRE  */
	         + sizeof(ttl);                  /* MINIMUM */

	if (rdlength + m->len > DGRAM_MAX_SIZE)
		return -1;
	rdlength = htons(rdlength);

	msgref(m, off);         /* NAME       */
	msg16(m, htons(Q_SOA)); /* TYPE       */
	msg16(m, htons(Q_IN));  /* CLASS      */

	msg32(m, ttl);          /* TTL        */
	msg16(m, rdlength);     /* RDLENGTH   */
	                        /* RDATA      */
	msglabel(m, "ns1");        /* MNAME   */
	msgref(m, off);
	msglabel(m, "hostmaster"); /*  RNAME  */
	msgref(m, off);
	msg32(m, serial);          /* SERIAL  */
	msg32(m, ttl);             /* REFRESH */
	msg32(m, ttl);             /* RETRY   */
	msg32(m, ttl);             /* EXPIRE  */
	msg32(m, ttl);             /* MINIMUM */
	return 0;
}

static int
reply_ns(msg_t *m, name_t *query, name_t *tld, ipv4_t hostip)
{
	ssize_t off;
	uint16_t rdlength;
	uint32_t ttl = htonl(TTL);

	off = name_search(query, tld);
	if (off < 0) {
		debugf("did not find base domain as suffix of query; refusing\n");
		reply(m, REPLY_REFUSED);
		return 0;
	}

	if (off != 0)
		return reply_soa(m, query, tld, 1);

	msg_prep_reply(m, F_AA);
	m->an_count = htons(2);
	m->ar_count = htons(2);
	msg_commit(m);

	/*************************** NAMESERVER RECORDS */
	rdlength = namelen("ns1") + 2; /* NSDNAME */
	if (rdlength * 2 + m->len > DGRAM_MAX_SIZE)
		return -1;
	rdlength = htons(rdlength);

	/* IN NS ns1 */
	msgref(m, off);         /* NAME       */
	msg16(m, htons(Q_NS));  /* TYPE       */
	msg16(m, htons(Q_IN));  /* CLASS      */

	msg32(m, ttl);          /* TTL        */
	msg16(m, rdlength);     /* RDLENGTH   */
	                        /* RDATA      */
	msglabel(m, "ns1");        /* NSDNAME */
	msgref(m, off);

	/* IN NS ns2 */
	msgref(m, off);         /* NAME       */
	msg16(m, htons(Q_NS));  /* TYPE       */
	msg16(m, htons(Q_IN));  /* CLASS      */

	msg32(m, ttl);          /* TTL        */
	msg16(m, rdlength);     /* RDLENGTH   */
	                        /* RDATA      */
	msglabel(m, "ns2");        /* NSDNAME */
	msgref(m, off);


	/****************************** ADDRESS RECORDS */
	rdlength = sizeof(hostip); /* ADDRESS */
	if (rdlength * 2 + m->len > DGRAM_MAX_SIZE)
		return -1;
	rdlength = htons(rdlength);

	/* IN A ns1 */
	msglabel(m, "ns1");     /* NAME       */
	msgref(m, off);
	msg16(m, htons(Q_A));   /* TYPE       */
	msg16(m, htons(Q_IN));  /* CLASS      */

	msg32(m, ttl);          /* TTL        */
	msg16(m, rdlength);     /* RDLENGTH   */
	                        /* RDATA      */
	msg32(m, hostip);          /* ADDRESS */

	/* IN A ns2 */
	msglabel(m, "ns2");     /* NAME       */
	msgref(m, off);
	msg16(m, htons(Q_A));   /* TYPE       */
	msg16(m, htons(Q_IN));  /* CLASS      */

	msg32(m, ttl);          /* TTL        */
	msg16(m, rdlength);     /* RDLENGTH   */
	                        /* RDATA      */
	msg32(m, hostip);          /* ADDRESS */

	return 0;
}

static int
reply_aaaa(msg_t *m)
{
	msg_prep_reply(m, F_NOERROR);
	m->qd_count = htons(1);
	m->an_count = htons(0);
	msg_commit(m);

	return 0;
}

static int
reply_a(msg_t *m, ipv4_t ip)
{
	uint16_t rdlength;
	uint32_t ttl = htonl(TTL);

	msg_prep_reply(m, F_AA);
	m->qd_count = htons(1);
	m->an_count = htons(1);
	msg_commit(m);

	rdlength = sizeof(ip); /* ADDRESS */

	if (rdlength + m->len > DGRAM_MAX_SIZE)
		return -1;
	rdlength = htons(rdlength);

	/* IN A <query> */
	msgref(m, 0);           /* NAME       */
	msg16(m, htons(Q_A));   /* TYPE       */
	msg16(m, htons(Q_IN));  /* CLASS      */

	msg32(m, ttl);          /* TTL        */
	msg16(m, rdlength);     /* RDLENGTH   */
	                        /* RDATA      */
	msg32(m, ip);              /* ADDRESS */

	return 0;
}

static int
reply_magic_a(msg_t *m, name_t *query, name_t *tld)
{
	ipv4_t ip;

	ip = name_ip(query, tld);
	if (!ip || ip == BADIP) {
		debugf("failed to extract IPv4 address from query; replying NXDOMAIN\n");
		reply(m, REPLY_NXDOMAIN);
		return 0;
	}

	return reply_a(m, ip);
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

	memset(&sa, 0, sizeof(sa)); /* specifically, clear SA_RESTART */
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

#define MAX_FIXED_ANSWER 8

int main(int argc, char **argv)
{
	int rc;

	int fd;
	struct sockaddr_in peer;
	socklen_t len;
	char peer_ip[INET6_ADDRSTRLEN];

	ssize_t n;
	msg_t msg;

	name_t *tld   = NULL; /* top-level domain */
	name_t *query = NULL;

	char *name = NULL;
	uint16_t qtype, qclass, v;
	ipv4_t ip, hostip,
	       a_replies[MAX_FIXED_ANSWER],
	       ns_replies[MAX_FIXED_ANSWER];
	int port, a_idx = 0, ns_idx = 0,
	    a_reply = 0, ns_reply = 0;
#ifdef TESTER
	int test_max = 0;
#endif

	struct timeval start, end;

	struct option long_opts[] = {
		{ "help",           no_argument, 0, 'h' },
		{ "version",        no_argument, 0, 'v' },
		{ "bind",     required_argument, 0, 'b' },
		{ "ns",       required_argument, 0, 'n' },
		{ "domain",   required_argument, 0, 'd' },
		{ "serial",   required_argument, 0, 's' },
#ifdef TESTER
		{ "max",      required_argument, 0, 257 },
#endif
		{ 0, 0, 0, 0 },
	};

	/* parse options */
	SERIAL = serial_parse("-");
	tld = name_parse("netip.cc");
	hostip = ip_parse("127.0.0.1");
	port = 53;
	for (;;) {
		int c = getopt_long(argc, argv, "hvb:a:n:r:d:s:", long_opts, NULL);
		if (c == -1) break;

		switch (c) {
		case '?':
		case 'h':
			printf("netip " VERSION " - a fast, echo-response DNS server\n"
			       "Copyright (c) James Hunt <james@niftylogic.com>\n"
#ifdef TESTER
			       "\n"
			       "WARNING - this build of netip was made for testing purposes,\n"
			       "          so it may not be as performant as you would like,\n"
			       "          and it just might feature interesting short-circuit\n"
			       "          functionality not suitable for production use.\n"
#endif
#ifdef FUZZ
			       "\n"
			       "WARNING - this build of netip was made for afl-fuzz testing,\n"
			       "          so it may not be as performant as you would like.\n"
#endif
			       "\n"
			       "USAGE: %s [-b host:port] [-n base.tld]\n"
			       "\n"
			       "OPTIONS:\n"
			       "\n"
			       "  -h, --help     Show the help screen\n"
			       "  -v, --version  Show version information\n"
			       "  -b, --bind     Host IP address and port to bind (UDP)\n"
			       "                 (defaults to 127.0.0.1:53)\n"
			       "  -a             IP address(es) for answering IN A queries\n"
			       "  -n, --ns       IP address(es) for answering IN NS queries\n"
			       "  -d, --domain   Toplevel domain to resolve for\n"
			       "                 (defaults to netip.cc)\n"
			       "  -s, --serial   Set the SOA zone serial.  If set to '-',\n"
			       "                 the current epoch timestamp is used (default)\n"
#ifdef TESTER
			       "  --max N        Maximum number of queries to field before\n"
			       "                 exiting (for TESTING PURPOSES only)\n"
#endif
			       "\n"
			       "netip does not daemonize; if you want to run it in the\n"
			       "background, you will need to arrange something yourself.\n"
			       "\n"
			       "Error and warning messages will be printed to standard\n"
			       "error; statistics will go to standard output.\n"
			       "\n", argv[0]);
			return 0;

		case 'v':
			printf("netip " VERSION " - a fast, echo-response DNS server\n"
			       "Copyright (c) James Hunt <james@niftylogic.com>\n");
			return 0;

		case 'b':
			rc = bind_parse(optarg, &hostip, &port);
			if (rc != 0) {
				errorf("invalid --bind address '%s'\n", optarg);
				return 1;
			}
			break;

		case 'a':
			ip = ip_parse(optarg);
			if (!ip) {
				errorf("invalid -a (IN A) answer '%s'\n", optarg);
				return 1;
			}
			if (a_idx >= MAX_FIXED_ANSWER) {
				errorf("too many -a (IN A) answers specified (max: %d)\n", MAX_FIXED_ANSWER);
				return 1;
			}
			a_replies[a_idx++] = ip;
			break;

		case 'n':
			ip = ip_parse(optarg);
			if (!ip) {
				errorf("invalid -n (IN NS) answer '%s'\n", optarg);
				return 1;
			}
			if (ns_idx >= MAX_FIXED_ANSWER) {
				errorf("too many -n (IN NS) answers specified (max: %d)\n", MAX_FIXED_ANSWER);
				return 1;
			}
			ns_replies[ns_idx++] = ip;
			break;

		case 'd':
			free(tld);
			tld = name_parse(optarg);
			break;

		case 's':
			SERIAL = serial_parse(optarg);
			break;

#ifdef TESTER
		case 257: /* --max */
			test_max = atoi(optarg);
			break;
#endif
		}
	}
	if (!a_idx) {
		a_replies[a_idx++] = hostip;
	}
	debugf("loading %d answer(s) for IN A www.%s queries\n", a_idx, domain)

	if (!ns_idx) {
		ns_replies[ns_idx++] = hostip;
	}
	debugf("loading %d answer(s) for IN NS %s queries\n", ns_idx, domain)

	if (!SERIAL) {
		errorf("unable to automatically determine SOA serial: %s (error %d)\n",
			strerror(errno), errno);
		return 1;
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
	fd = listen_on(hostip, port);
	if (fd < 0) {
		return 1;
	}
#endif

#ifdef TESTER
	while (test_max-- > 0) {
#else
	for (;;) {
#endif
		qtype  = 0;
		qclass = 0;

#ifndef FUZZ
		len = sizeof(peer);
		debugf("waiting to receive up to %d bytes on fd %d\n", DGRAM_MAX_SIZE, fd);
		msg.len = recvfrom(fd, msg.data, DGRAM_MAX_SIZE,
			MSG_WAITALL, (struct sockaddr*)&peer, &len);
		if (msg.len < 0) {
			if (DO_SHUTDOWN) break;
			errorf("failed to recvfrom() client: %s (error %d)\n",
				strerror(errno), errno);
			NEXT;
		}

		rc = gettimeofday(&start, NULL);
		if (rc != 0) {
			errorf("unexpected error encountered during gettimeofday(start): %s (error %d)\n",
				strerror(errno), errno);
			memset(&start, 0, sizeof(start));
		}

		if (inet_ntop(AF_INET, &peer.sin_addr.s_addr, peer_ip, INET6_ADDRSTRLEN)) {
			debugf("received query from %s:%d\n", peer_ip, ntohs(peer.sin_port));
		} else {
			errorf("received query from unknown client (%s, error %d)\n",
				strerror(errno), errno);
		}
#else
		msg.len = read(fd, msg.data, DGRAM_MAX_SIZE);
		if (msg.len < 0) {
			if (DO_SHUTDOWN) break;
			errorf("failed to read from fd %d: %s (error %d)\n",
				fd, strerror(errno), errno);
			NEXT;
		}
#endif

		hexdump(stderr, msg.data, msg.len);

		if (msg.len < DGRAM_HEADER_SIZE) {
			debugf("short packet of %li octets received; ignoring\n", msg.len);
			NEXT;
		}
		msg.dend = &msg.data[0] + msg.len;
		memcpy(&msg, msg.data, DGRAM_HEADER_SIZE);
		msg.flags = ntohs(msg.flags);

		pktdump(stderr, &msg);

		if (QR(msg) || AA(msg) || TC(msg) || RA(msg) || OPCODE(msg)) {
			debugf("malformed query packet; refusing\n");
			reply(&msg, REPLY_REFUSED);
			goto reply;
		}
		if (ntohs(msg.qd_count) != 1) {
			debugf("malformed query packet (QD_COUNT != 1); refusing\n");
			reply(&msg, REPLY_REFUSED);
			goto reply;
		}

		query = name_extract(msg.data + DGRAM_HEADER_SIZE, msg.len - DGRAM_HEADER_SIZE);
		if (!query) {
			debugf("unable to extract QNAME; refusing\n");
			reply(&msg, REPLY_REFUSED);
			goto reply;
		}
		if (DGRAM_HEADER_SIZE + query->len + 4 > msg.len) {
			debugf("query is too short; refusing\n");
			reply(&msg, REPLY_REFUSED);
			goto reply;
		}
		memcpy(&qtype,  msg.data + DGRAM_HEADER_SIZE + query->len,     sizeof(qtype));  qtype  = ntohs(qtype);
		memcpy(&qclass, msg.data + DGRAM_HEADER_SIZE + query->len + 2, sizeof(qclass)); qclass = ntohs(qclass);

		fprintf(stderr, "qtype = %04x %04x\n", qtype, qclass);
		name = name_string(query);
		fprintf(stderr, "recv %s %s %s\n", qclass_name(qclass), qtype_name(qtype), name);
		switch (Q(qclass, qtype)) {
		case Q_IN_SOA:
			debugf("replying to IN SOA query\n");
			rc = reply_soa(&msg, query, tld, 0);
			if (rc != 0) NEXT;
			goto reply;

		case Q_IN_NS:
			debugf("replying to IN NS query\n");
			rc = reply_a(&msg, ns_replies[ns_reply]);
			ns_reply = (ns_reply + 1) % ns_idx;
			if (rc != 0) NEXT;
			goto reply;

		case Q_IN_A:
			debugf("replying to IN A query\n");
			if (ns_idx >= 1 && name_is(query, "ns1", tld)) {
				rc = reply_a(&msg, ns_replies[0]);

			} else if (ns_idx >= 2 && name_is(query, "ns2", tld)) {
				rc = reply_a(&msg, ns_replies[1]);

			} else if (ns_idx >= 3 && name_is(query, "ns3", tld)) {
				rc = reply_a(&msg, ns_replies[2]);

			} else if (ns_idx >= 4 && name_is(query, "ns4", tld)) {
				rc = reply_a(&msg, ns_replies[3]);

			} else if (ns_idx >= 5 && name_is(query, "ns5", tld)) {
				rc = reply_a(&msg, ns_replies[4]);

			} else if (ns_idx >= 6 && name_is(query, "ns6", tld)) {
				rc = reply_a(&msg, ns_replies[5]);

			} else if (ns_idx >= 7 && name_is(query, "ns7", tld)) {
				rc = reply_a(&msg, ns_replies[6]);

			} else if (ns_idx >= 8 && name_is(query, "ns8", tld)) {
				rc = reply_a(&msg, ns_replies[7]);

			} else if (name_is(query, "www", tld)
			        || name_eq(query,        tld)) {
				rc = reply_a(&msg, a_replies[a_reply]);
				a_reply = (a_reply + 1) % a_idx;

			} else {
				rc = reply_magic_a(&msg, query, tld);
			}
			if (rc != 0) NEXT;
			goto reply;

		case Q_IN_AAAA:
			debugf("replying to IN AAAA query\n");
			rc = reply_aaaa(&msg);
			if (rc != 0) NEXT;
			goto reply;

		default:
			debugf("unhandled query type %s %s received (%04x); refusing\n",
				qclass_name(qclass), qtype_name(qtype), Q(qclass, qtype));
			reply(&msg, REPLY_REFUSED);
			goto reply;
		}

reply:
		hexdump(stderr, msg.data, msg.len);
#ifndef FUZZ
		debugf("replying in %li bytes on fd %d\n", msg.len, fd);
		n = sendto(fd, msg.data, msg.len, 0, (struct sockaddr*)&peer, len);
		if (n < 0) {
			if (DO_SHUTDOWN) break;
			debugf("failed sending response: %s (error %d)\n",
				strerror(errno), errno);
			NEXT;
		}
		if (n != msg.len) {
			debugf("short write (only %li/%li bytes written)!\n", n, msg.len);
			NEXT;
		}

		rc = gettimeofday(&end, NULL);
		if (rc != 0) {
			errorf("unexpected error encountered during gettimeofday(start): %s (error %d)\n",
				strerror(errno), errno);

		} else if (start.tv_sec != 0) {
			unsigned long ts;

			if (end.tv_usec < start.tv_usec) {
				end.tv_usec += MICROSECONDS;
				end.tv_sec--;
			}

			ts = (end.tv_sec  - start.tv_sec) * MICROSECONDS
			   + (end.tv_usec - start.tv_usec);

			msg.flags = ntohs(msg.flags);
			printf("query %s %s %s rcode %02x %s %luus\n",
					qclass_name(qclass), qtype_name(qtype), name,
					RCODE(msg), (RCODE(msg) ? "invalid" : "valid"), ts);
		}
#endif
		free(name);  name  = NULL;
		free(query); query = NULL;

		NEXT;
	}

	free(tld);
	close(fd);
	return 0;
}
