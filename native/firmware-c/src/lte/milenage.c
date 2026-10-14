/*
 * MILENAGE (3GPP TS 35.206) for the current depot SIM batch. The example AES-based kernel: f1 for
 * network authentication, f2-f5 for RES, CK, IK and the anonymity key. All operations are built on
 * one AES-128 block encryption under the subscriber key Ki.
 */
#include <mbedtls/aes.h>
#include <string.h>

#include "gateway/lte.h"

/* r1..r5 rotation amounts and c1..c5 constants from TS 35.206 section 4.1. */
static const uint8_t ROT[5] = { 0, 0, 32, 64, 96 };

static int ki_encrypt(const uint8_t ki[16], const uint8_t in[16], uint8_t out[16])
{
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    int rc = mbedtls_aes_setkey_enc(&aes, ki, 128);
    if (rc == 0)
        rc = mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_ENCRYPT, in, out);
    mbedtls_aes_free(&aes);
    return rc;
}

static void xor16(uint8_t *dst, const uint8_t *a, const uint8_t *b)
{
    for (int i = 0; i < 16; i++)
        dst[i] = a[i] ^ b[i];
}

/* 128-bit left rotation by r bits (r is a multiple of 8 here). */
static void rot_bytes(uint8_t out[16], const uint8_t in[16], uint8_t r)
{
    uint8_t bytes = (uint8_t)(r / 8);
    for (int i = 0; i < 16; i++)
        out[i] = in[(i + bytes) % 16];
}

void milenage_opc(const uint8_t ki[16], const uint8_t op[16], uint8_t opc[16])
{
    uint8_t enc[16];
    ki_encrypt(ki, op, enc);
    xor16(opc, enc, op);
}

void milenage_f1(const uint8_t ki[16], const uint8_t opc[16], const uint8_t rand[16], const uint8_t sqn[6],
                 const uint8_t amf[2], uint8_t mac_a[8])
{
    uint8_t temp[16], in1[16], tmp[16], out1[16];

    uint8_t r[16];
    xor16(r, rand, opc);
    ki_encrypt(ki, r, temp);

    memcpy(in1, sqn, 6);
    memcpy(in1 + 6, amf, 2);
    memcpy(in1 + 8, sqn, 6);
    memcpy(in1 + 14, amf, 2);

    /* rotate IN1 by r1 = 0 and xor with OPc, then encrypt; c1 = 0. */
    memset(tmp, 0, sizeof tmp);
    for (int i = 0; i < 16; i++)
        tmp[(i + 8) % 16] ^= in1[i] ^ opc[i];
    xor16(tmp, tmp, temp);
    ki_encrypt(ki, tmp, out1);
    xor16(out1, out1, opc);
    memcpy(mac_a, out1, 8);
}

void milenage_f2345(const uint8_t ki[16], const uint8_t opc[16], const uint8_t rand[16], uint8_t res[8],
                    uint8_t ck[16], uint8_t ik[16], uint8_t ak[6])
{
    uint8_t temp[16], rotated[16], tmp[16], out[16];

    uint8_t r[16];
    xor16(r, rand, opc);
    ki_encrypt(ki, r, temp);

    /* f2/f5: rotate by r2 = 0, constant c2 (last byte 1). */
    xor16(tmp, temp, opc);
    tmp[15] ^= 1;
    ki_encrypt(ki, tmp, out);
    xor16(out, out, opc);
    memcpy(res, out + 8, 8);
    memcpy(ak, out, 6);

    /* f3 (CK): rotate by r3 = 32, constant c3 (last byte 2). */
    rot_bytes(rotated, temp, ROT[2]);
    xor16(tmp, rotated, opc);
    tmp[15] ^= 2;
    ki_encrypt(ki, tmp, ck);
    xor16(ck, ck, opc);

    /* f4 (IK): rotate by r4 = 64, constant c4 (last byte 4). */
    rot_bytes(rotated, temp, ROT[3]);
    xor16(tmp, rotated, opc);
    tmp[15] ^= 4;
    ki_encrypt(ki, tmp, ik);
    xor16(ik, ik, opc);
}
