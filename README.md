netip.cc
========

    netip 1.1 - a fast, echo-response DNS server
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

