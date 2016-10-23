default: netip
all: netip fuzzy tester

fuzzy: fuzzy.o
fuzzy.o: netip.c
	afl-clang $(CFLAGS) -DFUZZ -c -o $@ $+

tester: tester.o
tester.o: netip.c
	$(CC) $(CFLAGS) -DTESTER -c -o $@ $+

clean:
	rm -f *.o
	rm -f fuzzy netip
