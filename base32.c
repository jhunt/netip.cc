#include <stddef.h>
#include <string.h>

#include "base32.h"

#define MASK 0x1f

static char ALPHA[32] = "0123456789abcdefghijklmnopqrstuv";
static char LOOKUP[256] = {
	   0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
	   0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
	   0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
	   0, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,    0,    0,    0,    0,    0,    0,
	   0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
	   0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
	   0, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
	0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,    0,    0,    0,    0,    0,    0,    0,    0,    0,
	   0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
	   0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
	   0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
	   0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
	   0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
	   0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
	   0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
	   0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
};

void b32a(const char *alpha) {
	const char *c;
	memset(LOOKUP, 0, sizeof(LOOKUP));
	for (c = alpha; *c; c++) {
		ALPHA[c-alpha] = *c;
		LOOKUP[*c] = c-alpha;
	}
}

/*

          [0]      [1]      [2]      [3]      [4]
   8b: 01234567 01234567 01234567 01234567 01234567

   5b: 01234 56701 23456 70123 45670 12345 67012 34567
         ^     ^     ^     ^     ^     ^     ^     ^
         |     |     |     |     |     |     |     `------ (           [4]     ) & 01xf
         |     |     |     |     |     |     ` ----------- ([3] << 3 | [4] >> 5) & 0x1f
         |     |     |     |     |     `------------------ (           [3] >> 2) & 0x1f
         |     |     |     |     `------------------------ ([2] << 1 | [3] >> 7) & 0x1f
         |     |     |     `------------------------------ ([1] << 4 | [2] >> 4) & 0x1f
         |     |     `------------------------------------ (           [1] >> 1) & 0x1f
         |     `------------------------------------------ ([0] << 2 | [1] >> 6) & 0x1f
         `------------------------------------------------ (           [0] >> 3) & 0x1f

    01234567
    01234---   [0] >> 3

    01234567 01234567
    -----567 01------  [0] << 2 | [1] >> 6

             01234567
             --23456-  [1] >> 1

             01234567 01234567
             -------7 0123----  [1] << 4 | [2] >> 4

                      01234567 01234567
                      ----4567 0-------  [2] << 1 | [3] >> 7

                               01234567
                               -12345--  [3] >> 2

                               01234567 01234567
                               ------67 012----- [3] << 3 | [4] >> 5

                                        01234567
                                        ---34567 [4]

    01234 56701
    01234 567-- [0] << 3 | [1] >> 2

          56701 23456 70123
          ---01 23456 7----  [1] << 6 | [2] << 1 || [3] >> 4

                      70123 45670
                      -0123 4567-  [3] << 4 | [4] >> 1

                            45670 12345 67012
                            ----0 12345 67---  [4] << 7 | [5] << 2 | [6] >> 3

                                        67012 34567
                                        --012 34567  [6] << 5 | [7]

 */


int
b32e(char *dst, const char *src, size_t inlen)
{
	char buf[5];
	for (; inlen >= 5; src += 5, inlen -= 5) {
		*dst++ = ALPHA[ (                         (0xf8 & src[0]) >> 3) & MASK];
		*dst++ = ALPHA[ ((0x07 & src[0]) << 2) | ((0xc0 & src[1]) >> 6) & MASK];
		*dst++ = ALPHA[ (                         (0x7f & src[1]) >> 1) & MASK];
		*dst++ = ALPHA[ ((0x01 & src[1]) << 4) | ((0xf0 & src[2]) >> 4) & MASK];
		*dst++ = ALPHA[ ((0x0f & src[2]) << 1) | ((0x80 & src[3]) >> 7) & MASK];
		*dst++ = ALPHA[ (                         (0x7c & src[3]) >> 2) & MASK];
		*dst++ = ALPHA[ ((0x03 & src[3]) << 3) | ((0xe0 & src[4]) >> 5) & MASK];
		*dst++ = ALPHA[ (                         (0x1f & src[4])     ) & MASK];
	}

	if (inlen >= 1) {
		/* bounce through a temporary (stack-local)
		   buffer for our required 0-padding. */
		memset(buf, 0, 5);
		memcpy(buf, src, inlen);
		src = buf;

		*dst++ = ALPHA[ (                         (0xf8 & src[0]) >> 3) & MASK];
		*dst++ = ALPHA[ ((0x07 & src[0]) << 2) | ((0xc0 & src[1]) >> 6) & MASK];
	}
	if (inlen >= 2) {
		*dst++ = ALPHA[ (                         (0x7f & src[1]) >> 1) & MASK];
		*dst++ = ALPHA[ ((0x01 & src[1]) << 4) | ((0xf0 & src[2]) >> 4) & MASK];
	}
	if (inlen >= 3) {
		*dst++ = ALPHA[ ((0x0f & src[2]) << 1) | ((0x80 & src[3]) >> 7) & MASK];
	}
	if (inlen >= 4) {
		*dst++ = ALPHA[ (                         (0x7c & src[3]) >> 2) & MASK];
		*dst++ = ALPHA[ ((0x03 & src[3]) << 3) | ((0xe0 & src[4]) >> 5) & MASK];
	}
	return 0;
}

int
b32d(char *dst, const char *src, size_t inlen)
{
	switch (inlen % 8) {
	case 1: case 3: case 6:
		return 1;
	}

	for (; inlen >= 8; src += 8, inlen -= 8) {
		*dst++ = (LOOKUP[src[0]] << 3) | (LOOKUP[src[1]] >> 2);
		*dst++ = (LOOKUP[src[1]] << 6) | (LOOKUP[src[2]] << 1) | (LOOKUP[src[3]] >> 4);
		*dst++ = (LOOKUP[src[3]] << 4) | (LOOKUP[src[4]] >> 1);
		*dst++ = (LOOKUP[src[4]] << 7) | (LOOKUP[src[5]] << 2) | (LOOKUP[src[6]] >> 3);
		*dst++ = (LOOKUP[src[6]] << 5) | (LOOKUP[src[7]]);
	}
	if (inlen >= 2) *dst++ = (LOOKUP[src[0]] << 3) | (LOOKUP[src[1]] >> 2);
	if (inlen >= 4) *dst++ = (LOOKUP[src[1]] << 6) | (LOOKUP[src[2]] << 1) | (LOOKUP[src[3]] >> 4);
	if (inlen >= 5) *dst++ = (LOOKUP[src[3]] << 4) | (LOOKUP[src[4]] >> 1);
	if (inlen >= 7) *dst++ = (LOOKUP[src[4]] << 7) | (LOOKUP[src[5]] << 2) | (LOOKUP[src[6]] >> 3);
	return 0;
}

#ifdef O_TESTS
#include "ctap.h"

#define b32_is(buf, in, out) do {\
	memset(buf, 0, sizeof(buf)); \
	ok(b32e(buf, in, strlen(in)) == 0, "b32e(" in ") should succeed"); \
	buf[b32elen(strlen(in))] = '\0'; \
	is(buf, out, "[" in "] is [" out "] in base32"); \
	\
	memset(buf, 0, sizeof(buf)); \
	ok(b32d(buf, out, strlen(out)) == 0, "b32d(" out ") should succeed"); \
	buf[b32dlen(strlen(out))] = '\0'; \
	is(buf, in, "[" out "] in base32 is [" in "]"); \
} while (0)

#define b32_uses(e,d) do {\
	cmp_ok(b32elen(e), "==", d, "base-32 needs %d bytes to encode %d bytes", e, d); \
	cmp_ok(b32dlen(d), "==", e, "base-32 needs %d bytes to decode %d bytes", d, e); \
} while (0)

#define b32_noop(buf, s) do {\
	memset(buf, 0, sizeof(buf)); \
	ok(b32e(buf, s, strlen(s)) == 0, "b32e(" s ") should succeed"); \
	ok(b32d(buf, buf, strlen(buf)) == 0, "b32d(b32e(" s ")) should also succeed"); \
	buf[b32dlen(b32elen(strlen(s)))] = '\0'; \
	is(buf, s, "D(E(s)) should equal (s)"); \
} while (0)

TESTS {
	char buf[256];

	b32_uses(1,2); b32_uses(2,4); b32_uses(3,5);
	b32_uses(4,7); /* and repeat! */

	b32_is(buf, "f",      "co");
	b32_is(buf, "fo",     "cpng");
	b32_is(buf, "foo",    "cpnmu");
	b32_is(buf, "foob",   "cpnmuog");
	b32_is(buf, "fooba",  "cpnmuoj1");
	b32_is(buf, "foobar", "cpnmuoj1e8");
	b32_is(buf, "\xbb\x68\x4a\x7c\x13\xa4\x77\xf4\x05\x18\xa4\x80", "ndk4kv0jkhrv818oki00");

	b32_noop(buf, "people say nothing is impossible, but i do nothing every day.");
	b32_noop(buf, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789");
}
#endif
