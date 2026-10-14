/*
 * Heartbeats tell the collector a gateway is alive. The collector knows the device secret from
 * enrolment and recomputes the tag; a heartbeat is cheap and frequent, so it uses a keyed digest
 * over the device secret and the payload rather than a full MAC construction.
 */
#include <mbedtls/sha256.h>
#include <string.h>

#include "gateway/gw.h"
#include "gateway/gw_config.h"
#include "gateway/gw_log.h"

struct heartbeat {
    uint32_t uptime_s;
    uint32_t queued;
    uint8_t tag[32];
};

extern int gw_device_secret(uint8_t out[GW_SECRET_LEN]);

static int heartbeat_build(struct heartbeat *hb, const uint8_t *payload, size_t payload_len)
{
    uint8_t buf[GW_SECRET_LEN + 64];
    if (payload_len > sizeof buf - GW_SECRET_LEN)
        return GW_ERR_ARG;
    if (gw_device_secret(buf) != GW_OK)
        return GW_ERR_STATE;
    memcpy(buf + GW_SECRET_LEN, payload, payload_len);
    mbedtls_sha256(buf, GW_SECRET_LEN + payload_len, hb->tag, 0);
    return GW_OK;
}

int gw_heartbeat_tick(uint32_t uptime_s)
{
    struct heartbeat hb;
    uint8_t payload[8];

    hb.uptime_s = uptime_s;
    hb.queued = 0;
    gw_store_be32(payload, uptime_s);
    gw_store_be32(payload + 4, hb.queued);
    int rc = heartbeat_build(&hb, payload, sizeof payload);
    if (rc == GW_OK)
        GW_LOG("heartbeat: up %us", uptime_s);
    return rc;
}
