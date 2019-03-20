netip.cc
========

    netip 1.2 - a fast, echo-response DNS server
    Copyright (c) James Hunt <james@niftylogic.com>

    USAGE: ./netip [-b host:port] [-n base.tld]

    OPTIONS:

      -h, --help     Show the help screen
      -v, --version  Show version information
      -b, --bind     Host IP address and port to bind (UDP)
                     (defaults to 127.0.0.1:53)
      -d, --domain   Toplevel domain to resolve for
                     (defaults to netip.cc)
      -s, --serial   Set the SOA zone serial.  If set to '-',
                     the current epoch timestamp is used (default)

    netip does not daemonize; if you want to run it in the
    background, you will need to arrange something yourself.

    Error and warning messages will be printed to standard
    error; statistics will go to standard output.


Docker
------

If you want to run this software via Docker (or your cgroups
orchestrator of choice), we have an image for you!

    docker run -d --restart=always huntprod/netip.cc:1.2

This will run a netip instance for the `netip.cc` domain, bound to
the first non-loopback interface inside the container.  You
probably want to forward the traffic back out:

    docker run -d --restart=always \
               -p 53:53/udp \
               huntprod/netip.cc:1.2

The following environment variables can be set via `-e`:

- **BIND_IP** - The IP address to bind (via UDP/53) to and listen
  for incoming DNS queries.

- **DOMAIN** - The domain to serve; the `netip.cc` of
  `a.b.c.d.netip.cc`; defaults accordingly.
