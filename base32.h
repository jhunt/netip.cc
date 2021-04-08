#ifndef BASE32_H
#define BASE32_H

#define BASE32_ALPHA     "abcdefghijklmnopqrstuvwxyz234567"
#define BASE32_HEX_ALPHA "0123456789abcdefghijklmnopqrstuv"

static inline size_t
b32elen(size_t dlen) {
	return (8*dlen) / 5 + (8*dlen % 5 == 0 ? 0 : 1);
}

static inline size_t
b32dlen(size_t elen) {
	return (5*elen) / 8;
}

void b32a(const char *alpha);
int b32d(char *dst, const char *src, size_t len);
int b32e(char *dst, const char *src, size_t len);

#endif
