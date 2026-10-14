/*
 * Build settings for the gateway firmware. The curve here is the device identity curve; the SoC and
 * the depot network dictate the rest.
 */
#ifndef GW_CONFIG_H
#define GW_CONFIG_H

#include <mbedtls/ecp.h>

/* Device identity key, generated once on first boot and kept in the secure element. */
#define GW_DEVICE_CURVE MBEDTLS_ECP_DP_SECP256R1

#define GW_SECRET_LEN 32
#define GW_UPLINK_HOST "uplink.tallowbrook.example"
#define GW_UPLINK_PORT 8883
#define GW_TELEMETRY_QUEUE 256
#define GW_HEARTBEAT_INTERVAL_S 30
#define GW_MAX_IMAGE (16u * 1024u * 1024u)

#endif
