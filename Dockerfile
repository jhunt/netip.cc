FROM alpine:3.5 AS build
RUN apk update \
 && apk add git make gcc libc-dev
COPY * /build/
RUN cd /build \
 && make clean \
 && make netip \
 && chmod 0755 netip


FROM alpine:3.5
MAINTAINER James Hunt <james@huntprod.com>
COPY --from=build /build/netip /usr/bin/netip
COPY aux/netip /netip

EXPOSE 53/udp
ENTRYPOINT ["/netip"]
