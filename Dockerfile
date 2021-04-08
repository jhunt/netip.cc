FROM alpine:3 AS build
RUN apk update \
 && apk add git make gcc libc-dev libsodium-dev
WORKDIR /build
COPY . .
RUN make clean netip \
 && chmod 0755 netip


FROM alpine:3

ARG BUILD_DATE
ARG VCS_REF
LABEL maintainer="James Hunt <images@huntprod.com>" \
      summary="Run netip.cc in a container (or two)" \
      org.label-schema.build-date=$BUILD_DATE \
      org.label-schema.vcs-url="https://github.com/jhunt/netip.cc.git" \
      org.label-schema.vcs-ref=$VCS_REF \
      org.label-schema.schema-version="1.0.0"

RUN apk update \
 && apk add libsodium

COPY --from=build /build/netip /usr/bin/netip
COPY aux/netip /netip

EXPOSE 53/udp
ENTRYPOINT ["/netip"]
