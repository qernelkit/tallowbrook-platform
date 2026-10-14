/*
 * Seeding the per-clip key. The NVR has no /dev/random worth trusting early at boot, so the clip
 * keys are seeded straight from the CPU: RDSEED for a true-random seed, RDRAND as the fallback when
 * RDSEED is starved. Both are gated on CPUID in cpu_features.c.
 */
#include "edgeclip.h"

#include <immintrin.h>

#define RDSEED_TRIES 32
#define RDRAND_TRIES 32

static int seed_from_rdseed(uint8_t *out, size_t len)
{
    for (size_t off = 0; off < len; off += 8) {
        unsigned long long word = 0;
        int ok = 0;
        for (int i = 0; i < RDSEED_TRIES && !ok; i++) {
            if (_rdseed64_step(&word))
                ok = 1;
            else
                _mm_pause();
        }
        if (!ok)
            return -1;
        size_t chunk = len - off < 8 ? len - off : 8;
        for (size_t b = 0; b < chunk; b++)
            out[off + b] = (uint8_t)(word >> (8 * b));
    }
    return 0;
}

static int seed_from_rdrand(uint8_t *out, size_t len)
{
    for (size_t off = 0; off < len; off += 8) {
        unsigned long long word = 0;
        int ok = 0;
        for (int i = 0; i < RDRAND_TRIES && !ok; i++) {
            if (_rdrand64_step(&word))
                ok = 1;
        }
        if (!ok)
            return -1;
        size_t chunk = len - off < 8 ? len - off : 8;
        for (size_t b = 0; b < chunk; b++)
            out[off + b] = (uint8_t)(word >> (8 * b));
    }
    return 0;
}

int seed_clip_key(const struct cpu_features *f, uint8_t key[16])
{
    if (f->rdseed && seed_from_rdseed(key, 16) == 0)
        return 0;
    if (f->rdrand && seed_from_rdrand(key, 16) == 0)
        return 0;
    return -1;
}
