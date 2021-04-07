#include <stddef.h>
#include <string.h>

#include "base16.h"

static char ALPHA[16] = "0123456789abcdef";
static char LOOKUP[256] = {
	   0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
	   0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
	   0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
	   0, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,    0,    0,    0,    0,    0,    0,
	   0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
	   0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
	   0, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,    0,    0,    0,    0,    0,    0,    0,    0,    0,
	   0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
	   0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
	   0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
	   0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
	   0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
	   0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
	   0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
	   0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
	   0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
};

void b16a(const char *alpha) {
	const char *c;
	memset(LOOKUP, 0, sizeof(LOOKUP));
	for (c = alpha; *c; c++) {
		ALPHA[c-alpha] = *c;
		LOOKUP[*c] = c-alpha;
	}
}

/*

          [0]
   1b: 01234567

   2b: 0123 4567
         ^    ^
         |    `--- ([0]     ) & 0x0f
         `-------- ([0] >> 4) & 0x0f

    01234567
    0123----  [0] >> 4

    01234567
    ----4567  [0]


    0123 4567
    0123 4567   [0] << 4 | [1]

 */


int
b16e(char *dst, const char *src, size_t inlen)
{
	for (; inlen > 0; src += 1, inlen -= 1) {
		*dst++ = ALPHA[(0xf0 & src[0]) >> 4];
		*dst++ = ALPHA[(0x0f & src[0])     ];
	}
	return 0;
}

int
b16d(char *dst, const char *src, size_t inlen)
{
	if (inlen % 2 != 0)
		return 1;

	for (; inlen >= 2; src += 2, inlen -= 2) {
		*dst++ = (LOOKUP[src[0]] << 4) | (LOOKUP[src[1]]);
	}
	return 0;
}

#ifdef O_TESTS
#include "ctap.h"

#define b16_is(buf, in, out) do {\
	memset(buf, 0, sizeof(buf)); \
	ok(b16e(buf, in, strlen(in)) == 0, "b16e(" in ") should succeed"); \
	buf[b16elen(strlen(in))] = '\0'; \
	is(buf, out, "[" in "] is [" out "] in base16"); \
	\
	memset(buf, 0, sizeof(buf)); \
	ok(b16d(buf, out, strlen(out)) == 0, "b16d(" out ") should succeed"); \
	buf[b16dlen(strlen(out))] = '\0'; \
	is(buf, in, "[" out "] in base16 is [" in "]"); \
} while (0)

#define b16_uses(e,d) do {\
	cmp_ok(b16elen(e), "==", d, "base-16 needs %d bytes to encode %d bytes", e, d); \
	cmp_ok(b16dlen(d), "==", e, "base-16 needs %d bytes to decode %d bytes", d, e); \
} while (0)

#define b16_noop(buf, s) do {\
	memset(buf, 0, sizeof(buf)); \
	ok(b16e(buf, s, strlen(s)) == 0, "b16e(" s ") should succeed"); \
	ok(b16d(buf, buf, b16elen(strlen(s))) == 0, "b16d(b16e(" s ")) should also succeed"); \
	buf[b16dlen(b16elen(strlen(s)))] = '\0'; \
	is(buf, s, "D(E(s)) should equal (s)"); \
} while (0)

TESTS {
	char buf[256];

	b16_uses(1,2); b16_uses(2,4); b16_uses(3,6);
	b16_uses(4,8); /* you get the idea */

	cmp_ok(b16elen(7), "==", 14, "base-16 uses double the space for encoding");
	cmp_ok(b16dlen(14), "==", 7, "base-16 uses half the space for decoding");

	b16_is(buf, "f",      "66");
	b16_is(buf, "fo",     "666f");
	b16_is(buf, "foo",    "666f6f");
	b16_is(buf, "foob",   "666f6f62");
	b16_is(buf, "fooba",  "666f6f6261");
	b16_is(buf, "foobar", "666f6f626172");

	b16_noop(buf, "people say nothing is impossible, but i do nothing every day.");
	b16_noop(buf, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789");
}
#endif
