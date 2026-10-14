/*
 * Keccak-f[1600] permutation (FIPS 202), used by the TUAK algorithm set. Straightforward reference
 * implementation over a 25-lane state of 64-bit lanes.
 */
#include "gateway/lte.h"

static const uint64_t KECCAK_RC[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL, 0x8000000080008000ULL,
    0x000000000000808bULL, 0x0000000080000001ULL, 0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008aULL, 0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL, 0x000000000000800aULL, 0x800000008000000aULL,
    0x8000000080008081ULL, 0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL,
};

static const int KECCAK_ROT[24] = {
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
};

static const int KECCAK_PI[24] = {
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
};

static uint64_t rotl64(uint64_t x, int n)
{
    return (x << n) | (x >> (64 - n));
}

void keccak_f1600(uint64_t state[25])
{
    for (int round = 0; round < 24; round++) {
        uint64_t bc[5], t;

        for (int i = 0; i < 5; i++)
            bc[i] = state[i] ^ state[i + 5] ^ state[i + 10] ^ state[i + 15] ^ state[i + 20];
        for (int i = 0; i < 5; i++) {
            t = bc[(i + 4) % 5] ^ rotl64(bc[(i + 1) % 5], 1);
            for (int j = 0; j < 25; j += 5)
                state[j + i] ^= t;
        }

        t = state[1];
        for (int i = 0; i < 24; i++) {
            int j = KECCAK_PI[i];
            uint64_t tmp = state[j];
            state[j] = rotl64(t, KECCAK_ROT[i]);
            t = tmp;
        }

        for (int j = 0; j < 25; j += 5) {
            uint64_t row[5];
            for (int i = 0; i < 5; i++)
                row[i] = state[j + i];
            for (int i = 0; i < 5; i++)
                state[j + i] ^= (~row[(i + 1) % 5]) & row[(i + 2) % 5];
        }

        state[0] ^= KECCAK_RC[round];
    }
}
