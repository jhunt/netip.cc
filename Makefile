VERSION := 1.3
CPPFLAGS += -DVERSION=\"$(VERSION)\"

default: netip
all: netip fuzzy tester

docker:
	docker build \
	  --build-arg VERSION="$(VERSION)" \
	  --build-arg BUILD_DATE="$(shell date -u --iso-8601)" \
	  --build-arg VCS_REF="$(shell git rev-parse --short HEAD)" \
	  . -t huntprod/netip.cc:latest
	
	docker build -f Dockerfile.web \
	  --build-arg VERSION="$(VERSION)" \
	  --build-arg BUILD_DATE="$(shell date -u --iso-8601)" \
	  --build-arg VCS_REF="$(shell git rev-parse --short HEAD)" \
	  . -t huntprod/www.netip.cc:latest

push:
	docker tag huntprod/netip.cc:latest huntprod/netip.cc:$(VERSION)
	docker push huntprod/netip.cc:latest
	docker push huntprod/netip.cc:$(VERSION)
	
	docker tag huntprod/www.netip.cc:latest huntprod/www.netip.cc:$(VERSION)
	docker push huntprod/www.netip.cc:latest
	docker push huntprod/www.netip.cc:$(VERSION)

fuzzy: fuzzy.o
fuzzy.o: netip.c
	afl-clang $(CFLAGS) -DFUZZ -c -o $@ $+

tester: tester.o
tester.o: netip.c
	$(CC) $(CFLAGS) -DTESTER -c -o $@ $+

clean:
	rm -f *.o
	rm -f fuzzy netip
