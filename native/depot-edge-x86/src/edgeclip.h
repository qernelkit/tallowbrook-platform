/* edgeclip: fast clip encryption and fingerprinting for the depot NVR. */
#ifndef EDGECLIP_H
#define EDGECLIP_H

#include <stddef.h>
#include <stdint.h>

struct cpu_features {
    int aesni;
    int sse41;
    int sha;
    int rdrand;
    int rdseed;
};

void cpu_detect(struct cpu_features *f);

/* Seeds a 16-byte clip key: RDSEED preferred, RDRAND as a fallback, both gated on CPUID. */
int seed_clip_key(const struct cpu_features *f, uint8_t key[16]);

struct clip_ctr {
    uint8_t round_keys[176];
    uint8_t counter[16];
};

void clip_ctr_init(struct clip_ctr *ctx, const uint8_t key[16], const uint8_t iv[16]);
void clip_ctr_xcrypt(struct clip_ctr *ctx, const uint8_t *in, uint8_t *out, size_t len);

/* SHA-256 clip fingerprint on the SHA extensions. */
void clip_sha256(const uint8_t *data, size_t len, uint8_t out[32]);

#endif
