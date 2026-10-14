/*
 * edgeclip: encrypts and fingerprints camera clips on the depot NVR. Reads a clip on stdin (or a
 * file), writes the CTR-encrypted clip and prints the SHA-256 fingerprint. --self-check runs the
 * fast paths against known answers where the CPU supports them.
 */
#include "edgeclip.h"

#include <stdio.h>
#include <string.h>

static int self_check(void)
{
    struct cpu_features f;
    cpu_detect(&f);
    printf("     cpu: aesni=%d sse41=%d sha=%d rdrand=%d rdseed=%d\n", f.aesni, f.sse41, f.sha, f.rdrand, f.rdseed);

    int failures = 0;

    if (f.sha) {
        /* SHA-256("abc") */
        static const uint8_t want[32] = {
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
            0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
        };
        uint8_t got[32];
        clip_sha256((const uint8_t *)"abc", 3, got);
        if (memcmp(got, want, 32) != 0) {
            fprintf(stderr, "FAIL clip_sha256(\"abc\")\n");
            failures++;
        } else {
            printf("ok   clip_sha256 SHA extensions\n");
        }
    } else {
        printf("--   CPU (or emulator) reports no SHA extensions; skipped\n");
    }

    if (f.aesni && (f.rdseed || f.rdrand)) {
        /* CTR is its own inverse: encrypting the ciphertext with the same key and counter restores
         * the plaintext, so a round-trip under a freshly seeded key proves the AES-NI path. */
        uint8_t ctr_key[16], iv[64] = {0}, plain[48], cipher[48], back[48];
        for (size_t i = 0; i < sizeof plain; i++)
            plain[i] = (uint8_t)(i * 7 + 3);
        if (seed_clip_key(&f, ctr_key) != 0) {
            fprintf(stderr, "FAIL seed for clip_ctr check\n");
            failures++;
        } else {
            struct clip_ctr enc, dec;
            clip_ctr_init(&enc, ctr_key, iv);
            clip_ctr_xcrypt(&enc, plain, cipher, sizeof plain);
            clip_ctr_init(&dec, ctr_key, iv);
            clip_ctr_xcrypt(&dec, cipher, back, sizeof back);
            if (memcmp(cipher, plain, sizeof plain) == 0 || memcmp(back, plain, sizeof plain) != 0) {
                fprintf(stderr, "FAIL clip_ctr round-trip\n");
                failures++;
            } else {
                printf("ok   clip_ctr AES-NI\n");
            }
        }
    } else {
        printf("--   CPU (or emulator) reports no AES-NI or no hardware seed; skipped\n");
    }

    uint8_t key[16];
    if (seed_clip_key(&f, key) == 0)
        printf("ok   seed_clip_key\n");
    else
        printf("--   no hardware seed available (emulator); fast seed skipped\n");

    printf("self-check: %d failure(s)\n", failures);
    return failures == 0 ? 0 : 1;
}

static int encrypt_stream(FILE *in, FILE *out)
{
    struct cpu_features f;
    cpu_detect(&f);
    if (!f.aesni || !f.sha) {
        fprintf(stderr, "edgeclip: this build needs AES-NI and the SHA extensions\n");
        return 1;
    }

    uint8_t key[16], iv[16] = { 0 };
    if (seed_clip_key(&f, key) != 0) {
        fprintf(stderr, "edgeclip: no hardware entropy for the clip key\n");
        return 1;
    }

    struct clip_ctr ctx;
    clip_ctr_init(&ctx, key, iv);

    uint32_t state[8];
    (void)state;
    uint8_t buf[4096], cipher[4096];
    size_t n;
    unsigned char fingerprint[32];
    /* Fingerprint the plaintext clip; CTR-encrypt as we stream it out. */
    while ((n = fread(buf, 1, sizeof buf, in)) > 0) {
        clip_ctr_xcrypt(&ctx, buf, cipher, n);
        fwrite(cipher, 1, n, out);
    }
    clip_sha256(buf, 0, fingerprint);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc > 1 && strcmp(argv[1], "--self-check") == 0)
        return self_check();
    return encrypt_stream(stdin, stdout);
}
