/*
 * Helpers for buffers that hold secrets: wiping, constant-time comparison, and hex for logs and the
 * line protocol. No key handling here.
 */
#include "util/crypto_util.h"

#include <string.h>

static const char HEX_DIGITS[] = "0123456789abcdef";

void crypto_wipe(void *buf, size_t len)
{
    if (buf != NULL && len > 0)
        explicit_bzero(buf, len);
}

int crypto_memeq(const void *a, const void *b, size_t len)
{
    const volatile unsigned char *x = a;
    const volatile unsigned char *y = b;
    unsigned char diff = 0;

    for (size_t i = 0; i < len; i++)
        diff |= (unsigned char)(x[i] ^ y[i]);
    return diff == 0;
}

size_t crypto_hex_encode(char *out, size_t out_cap, const unsigned char *in, size_t in_len)
{
    if (out_cap < 2 * in_len + 1)
        return 0;
    for (size_t i = 0; i < in_len; i++) {
        out[2 * i] = HEX_DIGITS[in[i] >> 4];
        out[2 * i + 1] = HEX_DIGITS[in[i] & 0x0f];
    }
    out[2 * in_len] = '\0';
    return 2 * in_len;
}

static int nibble(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

int crypto_hex_decode(unsigned char *out, size_t out_cap, const char *in, size_t *out_len)
{
    size_t n = strlen(in);
    if (n % 2 != 0 || n / 2 > out_cap)
        return -1;
    for (size_t i = 0; i < n / 2; i++) {
        int hi = nibble(in[2 * i]);
        int lo = nibble(in[2 * i + 1]);
        if (hi < 0 || lo < 0)
            return -1;
        out[i] = (unsigned char)(hi << 4 | lo);
    }
    *out_len = n / 2;
    return 0;
}
