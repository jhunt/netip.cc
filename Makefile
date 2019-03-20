VERSION := 1.2
CPPFLAGS += -DVERSION=\"$(VERSION)\"

default: netip
all: netip fuzzy tester

docker:
	docker build -t huntprod/netip.cc:latest .
push:
	docker tag huntprod/netip.cc:latest huntprod/netip.cc:$(VERSION)
	docker push huntprod/netip.cc:latest
	docker push huntprod/netip.cc:$(VERSION)

fuzzy: fuzzy.o
fuzzy.o: netip.c
	afl-clang $(CFLAGS) -DFUZZ -c -o $@ $+

tester: tester.o
tester.o: netip.c
	$(CC) $(CFLAGS) -DTESTER -c -o $@ $+

clean:
	rm -f *.o
	rm -f fuzzy netip
