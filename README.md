netip.cc
========

    netip v1.0 - a fast, echo-response DNS server
    Copyright (C) James Hunt <james@niftylogic.com>

    USAGE: ./netip [-b host:port] [-n base.tld]

    OPTIONS:

      -h, --help    Show the help screen
      -b, --bind    Host IP address and port to bind (UDP)
                    (defaults to 127.0.0.1:53)
      -n, --name    Toplevel domain to resolve for
                    (defaults to netip.cc)

    netip does not daemonize; if you want to run it in the
    background, you will need to arrange something yourself.

    Error and warning messages will be printed to standard
    error; statistics will go to standard output.

