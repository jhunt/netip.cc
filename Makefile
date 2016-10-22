default: netip fuzzy

fuzzy: fuzzy.o
fuzzy.o: netip.c
	afl-clang $(CFLAGS) -DFUZZ -c -o $@ $+

clean:
	rm -f *.o
	rm -f fuzzy netip
