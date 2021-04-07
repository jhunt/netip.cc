#include <string.h>
#include <sodium.h>
#include <errno.h>
#include <time.h>
#include <assert.h>

#include "seal.h"
#include "base16.h"

int seal_init()
{
	return sodium_init();
}

char *
seal_keygen()
{
	char key[crypto_secretbox_KEYBYTES];
	char *encoded;

	randombytes_buf(key, crypto_secretbox_KEYBYTES);
	encoded = malloc(b16elen(crypto_secretbox_KEYBYTES) + 1);
	if (!encoded) return NULL;

	b16e(encoded, key, crypto_secretbox_KEYBYTES);
	encoded[b16elen(crypto_secretbox_KEYBYTES)] = '\0';
	return encoded;
}

ssize_t
seal(char **nonce, char **sealed, unsigned long until, const char *text, size_t len, const char *key)
{
	char *buf     = NULL,
	     *_sealed = NULL;
	char _nonce[crypto_secretbox_NONCEBYTES];

	/* check yo-self */
	assert(nonce  != NULL);
	assert(sealed != NULL);
	assert(text   != NULL);
	assert(key    != NULL);

	assert(until < 0xffffffffff); /* we only want 40 bits */
	assert(len < 4096); /* len has no business being astronomical */

	/* initialize to sane defaults;
	   this makes free(3) calls simpler.
	 */
	*nonce = *sealed = NULL;

	/* generate a random nonce (unencoded) */
	randombytes_buf(_nonce, crypto_secretbox_NONCEBYTES);
	memset(_nonce, 42, crypto_secretbox_NONCEBYTES);

	/* encode the nonce under base-32 */
	*nonce = malloc(ENCODED_NONCE_LEN);
	if (!*nonce) goto fail;
	b32e(*nonce, _nonce, sizeof(_nonce));

	/* allocate the payload input buffer:
	     5 bytes (40-bits) for the "freshness" indicator;
	     $len bytes for the provided message contents; and
	     enough bytes for the message auth (MAC)
	 */
	buf = malloc(len+5+crypto_secretbox_MACBYTES);
	if (!buf) goto fail;

	/* encode the freshness indicator into the first 5 bytes */
	buf[0] = ((0xff00000000 & until) >> 32);
	buf[1] = ((0x00ff000000 & until) >> 24);
	buf[2] = ((0x0000ff0000 & until) >> 16);
	buf[3] = ((0x000000ff00 & until) >>  8);
	buf[4] = ((0x00000000ff & until)      );

	/* copy the message text onto the end */
	memcpy(buf+5, text, len);

	/* allocate the encrypted output buffer (unencoded) */
	_sealed = malloc(len+5+crypto_secretbox_MACBYTES);
	if (!_sealed) goto fail;

	/* allocate the encrypted output buffer (encoded) */
	*sealed = malloc(b32elen(len+5+crypto_secretbox_MACBYTES));
	if (!*sealed) goto fail;

	/* encrypt! */
	crypto_secretbox_easy(_sealed, buf, len+5, _nonce, key);

	/* encode! */
	b32e(*sealed, _sealed, len+5+crypto_secretbox_MACBYTES);

	free(buf);
	free(_sealed);
	return b32elen(len+5+crypto_secretbox_MACBYTES);

fail:
	free(buf);
	free(_sealed);
	free(*nonce);
	free(*sealed);
	return -1;
}

#define MAX_SEALED_BYTES 512

char *
unseal(const char *nonce, char *sealed, size_t len, const char *key)
{
	char *text = NULL;
	char buf[MAX_SEALED_BYTES];
	char _nonce[crypto_secretbox_NONCEBYTES];
	unsigned long notafter;
	time_t now;

	assert(nonce  != NULL);
	assert(sealed != NULL);
	assert(key    != NULL);

	/* some length sanity checking */
	if (b32dlen(len) < 6 || b32dlen(len) > MAX_SEALED_BYTES) goto fail;

	/* decode the nonce */
	b32d(_nonce, nonce, ENCODED_NONCE_LEN);

	/* decode the input */
	fprintf(stderr, "len %li will decode to %li; of which 5 bytes are freshness\n", len, b32dlen(len));
	b32d(buf, sealed, len);
	len = b32dlen(len);

	/* decrypt the input */
	if (crypto_secretbox_open_easy(buf, buf, len, _nonce, key) != 0) {
		goto fail;
	}

	/* strip off the mac bytes */
	len -= crypto_secretbox_MACBYTES;

	/* check freshness */
	notafter = (((unsigned long)buf[0] << 32) & 0xff00000000)
	         | (((unsigned long)buf[1] << 24) & 0x00ff000000)
	         | (((unsigned long)buf[2] << 16) & 0x0000ff0000)
	         | (((unsigned long)buf[3] <<  8) & 0x000000ff00)
	         | (((unsigned long)buf[4]      ) & 0x00000000ff);
	now = time(NULL);
	if (now < 0) goto fail;
	if (now > notafter) {
		errno = EINVAL;
		goto fail;
	}

	/* extract the original payload */
	text = malloc(len-5+1);
	if (!text) goto fail;
	memset(text, 0, len-5+1);
	fprintf(stderr, "copying %li bytes into token; null-term at [%li]\n", len-5, len-5+1);
	memcpy(text, buf+5, len-5);
	return text;

fail:
	free(text);
	return NULL;
}
