CPPFLAGS += -DVERSION=\"$(VERSION)\"

default: netip
all: netip fuzzy tester

local:
	docker build \
	  --build-arg BUILD_DATE="$(shell date -u --iso-8601)" \
	  --build-arg VCS_REF="$(shell git rev-parse --short HEAD)" \
	  . -t huntprod/netip.cc:latest
	
	docker build -f Dockerfile.web \
	  --build-arg BUILD_DATE="$(shell date -u --iso-8601)" \
	  --build-arg VCS_REF="$(shell git rev-parse --short HEAD)" \
	  . -t huntprod/www.netip.cc:latest

release:
	@echo "Checking that VERSION was defined in the calling environment"
	@test -n "$(VERSION)"
	@echo "OK.  VERSION=$(VERSION)"
	docker build \
	  --build-arg VERSION="$(VERSION)" \
	  --build-arg BUILD_DATE="$(shell date -u --iso-8601)" \
	  --build-arg VCS_REF="$(shell git rev-parse --short HEAD)" \
	  . -t huntprod/netip.cc:latest
	
	docker tag huntprod/netip.cc:latest huntprod/netip.cc:$(VERSION)
	docker push huntprod/netip.cc:latest
	docker push huntprod/netip.cc:$(VERSION)
	
	docker build -f Dockerfile.web \
	  --build-arg VERSION="$(VERSION)" \
	  --build-arg BUILD_DATE="$(shell date -u --iso-8601)" \
	  --build-arg VCS_REF="$(shell git rev-parse --short HEAD)" \
	  . -t huntprod/www.netip.cc:latest
	
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
