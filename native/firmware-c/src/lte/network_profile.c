/*
 * Constants for the depot private LTE network: the PLMN, the authentication management field, and
 * the operator variant OP from which each SIM's OPc is derived at start-up.
 */
#include <string.h>

#include "gateway/lte.h"

#define DEPOT_PLMN "90128"

/* Operator variant for the depot network (TS 35.206 OP). OPc is derived per subscriber from this. */
static const uint8_t NETWORK_OP[16] = { 0xcd, 0x63, 0xcb, 0x71, 0x95, 0x4a, 0x9f, 0x4e, 0x48, 0xa5, 0x99, 0x4e, 0x37, 0xa0, 0x2b, 0xaf };

static const uint8_t NETWORK_AMF[2] = { 0x80, 0x00 };

void network_profile_opc(const uint8_t ki[16], uint8_t opc[16])
{
    milenage_opc(ki, NETWORK_OP, opc);
}

const char *network_profile_plmn(void)
{
    return DEPOT_PLMN;
}

void network_profile_amf(uint8_t amf[2])
{
    memcpy(amf, NETWORK_AMF, sizeof NETWORK_AMF);
}
