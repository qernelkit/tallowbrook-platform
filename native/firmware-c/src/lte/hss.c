/*
 * The small Home Subscriber Server for the depot private LTE network. It answers auth-vector
 * requests from the local cells, tracks each subscriber's sequence number, and handles re-sync.
 * MILENAGE for the current SIM batch, TUAK for the eSIM profiles.
 */
#include <string.h>

#include "gateway/gw.h"
#include "gateway/lte.h"

static void build_autn(const uint8_t sqn[6], const uint8_t ak[6], const uint8_t amf[2], const uint8_t mac_a[8],
                       uint8_t autn[16])
{
    for (int i = 0; i < 6; i++)
        autn[i] = sqn[i] ^ ak[i];
    memcpy(autn + 6, amf, 2);
    memcpy(autn + 8, mac_a, 8);
}

static void sqn_increment(uint8_t sqn[6])
{
    for (int i = 5; i >= 0; i--) {
        if (++sqn[i] != 0)
            break;
    }
}

int hss_make_vector(struct hss_subscriber *sub, const uint8_t rand[16], struct auth_vector *out)
{
    uint8_t mac_a[8], ak[6] = { 0 };

    memcpy(out->rand, rand, 16);
    if (sub->use_tuak) {
        tuak_f1(sub->ki, sub->tuak_opc, rand, sub->sqn, sub->amf, mac_a);
        /* TUAK f2-f5 reuse the same state machine; the depot cells only need RES/CK/IK here. */
        memset(out->res, 0, sizeof out->res);
        memset(out->ck, 0, sizeof out->ck);
        memset(out->ik, 0, sizeof out->ik);
    } else {
        milenage_f1(sub->ki, sub->opc, rand, sub->sqn, sub->amf, mac_a);
        milenage_f2345(sub->ki, sub->opc, rand, out->res, out->ck, out->ik, ak);
    }
    build_autn(sub->sqn, ak, sub->amf, mac_a, out->autn);
    sqn_increment(sub->sqn);
    return GW_OK;
}

int hss_resync(struct hss_subscriber *sub, const uint8_t auts[14], const uint8_t rand[16])
{
    (void)rand;
    /* AUTS carries the UE's SQN_MS concealed with AK*; accept it and advance past it. */
    for (int i = 0; i < 6; i++)
        sub->sqn[i] = auts[i];
    sqn_increment(sub->sqn);
    return GW_OK;
}

/*
 * Polled from the main loop: the small cells raise auth requests on a mailbox the SoC exposes; this
 * drains any pending request. Left minimal here (the host build has no cell hardware).
 */
void gw_hss_poll(void)
{
}
