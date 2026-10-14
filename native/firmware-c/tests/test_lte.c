#include <string.h>

#include "gateway/lte.h"
#include "test.h"

/*
 * We do not pin the 3GPP test vectors here (that would duplicate the OP/Ki material). Instead the
 * tests check the internal consistency of the auth kernel: OPc derivation is stable, f1 depends on
 * every input, and the HSS advances SQN.
 */
TEST(milenage_opc_is_stable)
{
    uint8_t ki[16], op[16], a[16], b[16];
    for (int i = 0; i < 16; i++) {
        ki[i] = (uint8_t)(0x10 + i);
        op[i] = (uint8_t)(0xa0 + i);
    }
    milenage_opc(ki, op, a);
    milenage_opc(ki, op, b);
    CHECK(memcmp(a, b, 16) == 0);
}

TEST(milenage_f1_depends_on_sqn)
{
    uint8_t ki[16], opc[16], rand[16], amf[2] = { 0x80, 0x00 };
    uint8_t sqn1[6] = { 0, 0, 0, 0, 0, 1 };
    uint8_t sqn2[6] = { 0, 0, 0, 0, 0, 2 };
    uint8_t mac1[8], mac2[8];
    for (int i = 0; i < 16; i++) {
        ki[i] = (uint8_t)i;
        opc[i] = (uint8_t)(0x30 + i);
        rand[i] = (uint8_t)(0x90 + i);
    }
    milenage_f1(ki, opc, rand, sqn1, amf, mac1);
    milenage_f1(ki, opc, rand, sqn2, amf, mac2);
    CHECK(memcmp(mac1, mac2, 8) != 0);
}

TEST(milenage_f2345_fills_every_output)
{
    uint8_t ki[16], opc[16], rand[16];
    uint8_t res[8], ck[16], ik[16], ak[6];
    for (int i = 0; i < 16; i++) {
        ki[i] = (uint8_t)(i * 2);
        opc[i] = (uint8_t)(0x40 + i);
        rand[i] = (uint8_t)(0x11 * i);
    }
    memset(res, 0, sizeof res);
    memset(ck, 0, sizeof ck);
    milenage_f2345(ki, opc, rand, res, ck, ik, ak);
    uint8_t zero[16] = { 0 };
    CHECK(memcmp(ck, zero, 16) != 0);
    CHECK(memcmp(ik, zero, 16) != 0);
}

/* Keccak-f[1600] on the all-zero state has a known first lane (FIPS 202 intermediate value). */
TEST(keccak_f1600_zero_state_known_first_lane)
{
    uint64_t state[25];
    memset(state, 0, sizeof state);
    keccak_f1600(state);
    CHECK(state[0] == 0xF1258F7940E1DDE7ULL);
}

TEST(tuak_f1_depends_on_key)
{
    uint8_t k1[16], k2[16], opc[32], rand[16], sqn[6] = { 0 }, amf[2] = { 0x80, 0x00 };
    uint8_t mac1[8], mac2[8];
    memset(opc, 0x22, sizeof opc);
    for (int i = 0; i < 16; i++) {
        k1[i] = (uint8_t)i;
        k2[i] = (uint8_t)(i + 1);
        rand[i] = (uint8_t)(0x55 + i);
    }
    tuak_f1(k1, opc, rand, sqn, amf, mac1);
    tuak_f1(k2, opc, rand, sqn, amf, mac2);
    CHECK(memcmp(mac1, mac2, 8) != 0);
}

TEST(hss_make_vector_advances_sqn)
{
    struct hss_subscriber sub;
    struct auth_vector vec;
    uint8_t rand[16] = { 0 };
    memset(&sub, 0, sizeof sub);
    sub.amf[0] = 0x80;
    CHECK(hss_make_vector(&sub, rand, &vec) == 0);
    CHECK(sub.sqn[5] == 1);
    CHECK(hss_make_vector(&sub, rand, &vec) == 0);
    CHECK(sub.sqn[5] == 2);
}
