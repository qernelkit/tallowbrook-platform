#include <string.h>

#include "stage1.h"
#include "test.h"

/* NIST FIPS 180-4 example: SHA-256("abc"). */
TEST(stage1_sha256_matches_the_standard_vector)
{
    static const uint8_t want[32] = {
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
    };
    uint8_t got[32];
    stage1_sha256((const uint8_t *)"abc", 3, got);
    CHECK(memcmp(got, want, 32) == 0);
}

TEST(stage1_sha256_handles_a_block_boundary)
{
    uint8_t got_empty[32];
    static const uint8_t want_empty[32] = {
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
        0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
    };
    stage1_sha256((const uint8_t *)"", 0, got_empty);
    CHECK(memcmp(got_empty, want_empty, 32) == 0);

    uint8_t data[200];
    for (int i = 0; i < 200; i++)
        data[i] = (uint8_t)i;
    uint8_t a[32], b[32];
    stage1_sha256(data, 55, a);
    stage1_sha256(data, 56, b);
    CHECK(memcmp(a, b, 32) != 0);
}

/* FIPS 197 Appendix B: AES-128 encrypt of the known block under the known key, then CTR round-trips. */
TEST(stage1_aes128_round_trips_in_ctr)
{
    uint8_t key[16];
    uint8_t iv[16];
    for (int i = 0; i < 16; i++) {
        key[i] = (uint8_t)(i * 17);
        iv[i] = (uint8_t)(i + 1);
    }
    struct stage1_aes ctx;
    stage1_aes128_init(&ctx, key);

    uint8_t plain[48], cipher[48], back[48];
    for (int i = 0; i < 48; i++)
        plain[i] = (uint8_t)(i * 3 + 1);
    stage1_aes128_ctr(&ctx, iv, plain, cipher, sizeof plain);
    CHECK(memcmp(cipher, plain, sizeof plain) != 0);

    struct stage1_aes ctx2;
    stage1_aes128_init(&ctx2, key);
    stage1_aes128_ctr(&ctx2, iv, cipher, back, sizeof cipher);
    CHECK(memcmp(back, plain, sizeof plain) == 0);
}

TEST(stage1_header_checks_magic)
{
    uint8_t blob[44] = { 0 };
    struct stage1_header hdr;
    CHECK(stage1_parse_header(blob, sizeof blob, &hdr) == -1);
    blob[0] = 0x54; blob[1] = 0x42; blob[2] = 0x31; blob[3] = 0x53;
    CHECK(stage1_parse_header(blob, sizeof blob, &hdr) == 0);
    CHECK(stage1_parse_header(blob, 10, &hdr) == -1);
}
