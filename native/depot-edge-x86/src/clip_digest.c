/*
 * SHA-256 clip fingerprints on the Intel SHA extensions (_mm_sha256rnds2_epu32 and friends), so the
 * NVR can fingerprint every clip it writes without stealing cycles from the encoders.
 * Implementation after Intel's SHA extension reference.
 */
#include "edgeclip.h"

#include <immintrin.h>
#include <string.h>

static const uint32_t K256[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

static void sha256_ni_block(uint32_t state[8], const uint8_t block[64])
{
    const __m128i shuf = _mm_set_epi64x(0x0c0d0e0f08090a0bULL, 0x0405060700010203ULL);
    __m128i state0 = _mm_loadu_si128((const __m128i *)&state[0]);
    __m128i state1 = _mm_loadu_si128((const __m128i *)&state[4]);
    __m128i tmp = _mm_shuffle_epi32(state0, 0xB1);
    state1 = _mm_shuffle_epi32(state1, 0x1B);
    __m128i abef = _mm_alignr_epi8(tmp, state1, 8);
    __m128i cdgh = _mm_blend_epi16(state1, tmp, 0xF0);

    __m128i save0 = abef, save1 = cdgh;
    __m128i msg[4];
    for (int i = 0; i < 4; i++)
        msg[i] = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i *)(block + i * 16)), shuf);

    for (int i = 0; i < 16; i++) {
        __m128i m = msg[i % 4];
        __m128i k = _mm_loadu_si128((const __m128i *)&K256[i * 4]);
        __m128i wk = _mm_add_epi32(m, k);
        cdgh = _mm_sha256rnds2_epu32(cdgh, abef, wk);
        __m128i hi = _mm_shuffle_epi32(wk, 0x0E);
        abef = _mm_sha256rnds2_epu32(abef, cdgh, hi);
        if (i < 12) {
            __m128i a = msg[i % 4], b = msg[(i + 1) % 4], c = msg[(i + 2) % 4], d = msg[(i + 3) % 4];
            a = _mm_sha256msg1_epu32(a, b);
            __m128i tmp2 = _mm_alignr_epi8(d, c, 4);
            a = _mm_add_epi32(a, tmp2);
            msg[i % 4] = _mm_sha256msg2_epu32(a, d);
        }
    }

    abef = _mm_add_epi32(abef, save0);
    cdgh = _mm_add_epi32(cdgh, save1);
    tmp = _mm_shuffle_epi32(abef, 0x1B);
    __m128i out1 = _mm_shuffle_epi32(cdgh, 0xB1);
    __m128i out0 = _mm_blend_epi16(tmp, out1, 0xF0);
    out1 = _mm_alignr_epi8(out1, tmp, 8);
    _mm_storeu_si128((__m128i *)&state[0], out0);
    _mm_storeu_si128((__m128i *)&state[4], out1);
}

void clip_sha256(const uint8_t *data, size_t len, uint8_t out[32])
{
    uint32_t state[8] = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };
    uint8_t block[64];
    uint64_t bits = (uint64_t)len * 8;
    size_t i = 0;

    while (len - i >= 64) {
        sha256_ni_block(state, data + i);
        i += 64;
    }
    size_t rem = len - i;
    memcpy(block, data + i, rem);
    block[rem++] = 0x80;
    if (rem > 56) {
        memset(block + rem, 0, 64 - rem);
        sha256_ni_block(state, block);
        rem = 0;
    }
    memset(block + rem, 0, 56 - rem);
    for (int b = 0; b < 8; b++)
        block[56 + b] = (uint8_t)(bits >> (56 - 8 * b));
    sha256_ni_block(state, block);

    for (int j = 0; j < 8; j++) {
        out[j * 4] = (uint8_t)(state[j] >> 24);
        out[j * 4 + 1] = (uint8_t)(state[j] >> 16);
        out[j * 4 + 2] = (uint8_t)(state[j] >> 8);
        out[j * 4 + 3] = (uint8_t)state[j];
    }
}
