/*
 * TUAK (3GPP TS 35.231) f1 for the newer eSIM profiles. TUAK builds its functions on Keccak-f[1600]:
 * the subscriber key, OPc, RAND and the instance/algonom inputs are packed into the 1600-bit state,
 * the permutation is applied, and the MAC is read out of the state.
 */
#include <string.h>

#include "gateway/lte.h"

static const uint8_t TUAK_ALGONAME[7] = "TUAK1.0";

#define TUAK_KECCAK_ITER 1

static void pack_state(uint64_t state[25], const uint8_t *in, size_t len)
{
    uint8_t bytes[200] = { 0 };
    memcpy(bytes, in, len < sizeof bytes ? len : sizeof bytes);
    for (int i = 0; i < 25; i++) {
        uint64_t lane = 0;
        for (int b = 0; b < 8; b++)
            lane |= (uint64_t)bytes[i * 8 + b] << (8 * b);
        state[i] = lane;
    }
}

void tuak_f1(const uint8_t k[16], const uint8_t opc[32], const uint8_t rand[16], const uint8_t sqn[6],
             const uint8_t amf[2], uint8_t mac_a[8])
{
    uint8_t in[200] = { 0 };
    uint64_t state[25];
    size_t off = 0;

    memcpy(in + off, TUAK_ALGONAME, sizeof TUAK_ALGONAME);
    off += 8;
    memcpy(in + off, opc, 32);
    off += 32;
    memcpy(in + off, rand, 16);
    off += 16;
    memcpy(in + off, k, 16);
    off += 16;
    memcpy(in + off, sqn, 6);
    off += 6;
    memcpy(in + off, amf, 2);

    pack_state(state, in, sizeof in);
    for (int i = 0; i < TUAK_KECCAK_ITER; i++)
        keccak_f1600(state);

    for (int b = 0; b < 8; b++)
        mac_a[b] = (uint8_t)(state[0] >> (8 * b));
}
