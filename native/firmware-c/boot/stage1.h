/* Stage-1 loader: self-contained SHA-256 and table AES-128, no libc crypto. */
#ifndef GW_STAGE1_H
#define GW_STAGE1_H

#include <stddef.h>
#include <stdint.h>

void stage1_sha256(const uint8_t *data, size_t len, uint8_t out[32]);

struct stage1_aes {
    uint8_t round_keys[176];
};

void stage1_aes128_init(struct stage1_aes *ctx, const uint8_t key[16]);
void stage1_aes128_ctr(struct stage1_aes *ctx, const uint8_t iv[16], const uint8_t *in, uint8_t *out, size_t len);

struct stage1_header {
    uint32_t magic;
    uint32_t load_addr;
    uint32_t length;
    uint8_t digest[32];
};

int stage1_parse_header(const uint8_t *blob, size_t len, struct stage1_header *out);

#endif
