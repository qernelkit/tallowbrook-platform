/* Memory and hex helpers shared by the modules that handle secrets. */
#ifndef KEYD_UTIL_SECRETS_H
#define KEYD_UTIL_SECRETS_H

#include <stddef.h>

void crypto_wipe(void *buf, size_t len);
int crypto_memeq(const void *a, const void *b, size_t len);
size_t crypto_hex_encode(char *out, size_t out_cap, const unsigned char *in, size_t in_len);
int crypto_hex_decode(unsigned char *out, size_t out_cap, const char *in, size_t *out_len);

#endif
