#ifndef __NETIP_SEAL_H
#define __NETIP_SEAL_H

#include <stddef.h>
#include <sodium.h>

#include "base32.h"
#define ENCODED_NONCE_LEN b32elen(crypto_secretbox_NONCEBYTES)

int seal_init();
char * seal_keygen();
ssize_t seal(char **nonce, char **sealed, unsigned long until, const char *text, size_t len, const char *key);
char * unseal(const char *nonce, char *sealed, size_t len, const char *key);

#endif
