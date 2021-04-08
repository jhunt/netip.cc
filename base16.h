#ifndef BASE16_H
#define BASE16_H

static inline size_t
b16elen(size_t dlen) {
	return dlen * 2;
}

static inline size_t
b16dlen(size_t elen) {
	return elen / 2;
}

void b16a(const char *alpha);
int b16d(char *dst, const char *src, size_t len);
int b16e(char *dst, const char *src, size_t len);

#endif
