/*
 * The device identity key. Generated on first boot into the SoC secure element and never leaves it;
 * the public key is read out at enrolment. The curve is set in gw_config.h so a product variant can
 * change it in one place.
 */
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/ecp.h>
#include <mbedtls/pk.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "gateway/gw.h"
#include "gateway/gw_config.h"
#include "gateway/gw_log.h"
#include "gateway/gw_paths.h"

extern mbedtls_ctr_drbg_context *gw_drbg_ctx(void);

static mbedtls_pk_context device_pk;
static int have_identity;
static uint8_t device_secret[GW_SECRET_LEN];
static int have_secret;

/* The heartbeat secret is written to the device by the enrolment service, which holds the matching
 * copy. It is read once at start-up. */
static int load_device_secret(void)
{
    FILE *fp = fopen(GW_STATE_DIR "/device.secret", "rb");
    if (fp == NULL)
        return GW_ERR_IO;
    size_t n = fread(device_secret, 1, sizeof device_secret, fp);
    fclose(fp);
    if (n != sizeof device_secret)
        return GW_ERR_IO;
    have_secret = 1;
    return GW_OK;
}

static int generate_identity(void)
{
    int rc = mbedtls_pk_setup(&device_pk, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
    if (rc != 0)
        return GW_ERR_CRYPTO;
    rc = mbedtls_ecp_gen_key(GW_DEVICE_CURVE, mbedtls_pk_ec(device_pk), mbedtls_ctr_drbg_random, gw_drbg_ctx());
    if (rc != 0) {
        GW_LOG_ERR("identity: key generation failed (-0x%04x)", (unsigned)-rc);
        return GW_ERR_CRYPTO;
    }
    return GW_OK;
}

int gw_device_identity_load_or_create(void)
{
    mbedtls_pk_init(&device_pk);
    int rc = mbedtls_pk_parse_keyfile(&device_pk, GW_DEVICE_KEY_PATH, NULL, mbedtls_ctr_drbg_random, gw_drbg_ctx());
    if (rc != 0) {
        GW_LOG("identity: generating a new device key");
        rc = generate_identity();
        if (rc != GW_OK)
            return rc;
    }
    have_identity = 1;
    load_device_secret();  /* best effort; the heartbeat stays quiet until it is provisioned */
    return GW_OK;
}

int gw_device_secret(uint8_t out[GW_SECRET_LEN])
{
    if (!have_secret && load_device_secret() != GW_OK)
        return GW_ERR_STATE;
    memcpy(out, device_secret, GW_SECRET_LEN);
    return GW_OK;
}

void gw_device_identity_free(void)
{
    if (have_identity)
        mbedtls_pk_free(&device_pk);
    have_identity = 0;
}
