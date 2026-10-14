/* Depot private LTE: MILENAGE for the current SIM batch, TUAK for the newer eSIM profiles. */
#ifndef GW_LTE_H
#define GW_LTE_H

#include <stdint.h>

/* MILENAGE (3GPP TS 35.206). ki and opc are 16 bytes. */
void milenage_f1(const uint8_t ki[16], const uint8_t opc[16], const uint8_t rand[16], const uint8_t sqn[6],
                 const uint8_t amf[2], uint8_t mac_a[8]);
void milenage_f2345(const uint8_t ki[16], const uint8_t opc[16], const uint8_t rand[16], uint8_t res[8],
                    uint8_t ck[16], uint8_t ik[16], uint8_t ak[6]);
void milenage_opc(const uint8_t ki[16], const uint8_t op[16], uint8_t opc[16]);

/* TUAK (3GPP TS 35.231) f1, on Keccak-f[1600]. */
void tuak_f1(const uint8_t k[16], const uint8_t opc[32], const uint8_t rand[16], const uint8_t sqn[6],
             const uint8_t amf[2], uint8_t mac_a[8]);

/* Keccak-f[1600] permutation over a 25-lane state. */
void keccak_f1600(uint64_t state[25]);

/* Auth-vector requests and SQN tracking. */
struct auth_vector {
    uint8_t rand[16];
    uint8_t autn[16];
    uint8_t res[8];
    uint8_t ck[16];
    uint8_t ik[16];
};

struct hss_subscriber {
    uint8_t ki[16];
    uint8_t opc[16];
    uint8_t sqn[6];
    uint8_t amf[2];
    int use_tuak;
    uint8_t tuak_opc[32];
};

int hss_make_vector(struct hss_subscriber *sub, const uint8_t rand[16], struct auth_vector *out);
int hss_resync(struct hss_subscriber *sub, const uint8_t auts[14], const uint8_t rand[16]);

#endif
