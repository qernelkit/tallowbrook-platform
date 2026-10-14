/*
 * Handheld scanner pairing over BLE. A warehouse scanner pairs with the gateway so it can hand off
 * scan events; the two do an X25519 exchange over the BLE link and derive a session key from the
 * shared secret. mbedTLS ECDH on Curve25519.
 */
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/ecdh.h>
#include <string.h>

#include "gateway/gw.h"
#include "gateway/gw_log.h"

extern mbedtls_ctr_drbg_context *gw_drbg_ctx(void);

#define SCANNER_PUB_LEN 32

struct scanner_session {
    mbedtls_ecdh_context ecdh;
    uint8_t shared[32];
    int established;
};

int scanner_pair_begin(struct scanner_session *s, uint8_t our_pub[SCANNER_PUB_LEN])
{
    mbedtls_ecdh_init(&s->ecdh);
    int rc = mbedtls_ecdh_setup(&s->ecdh, MBEDTLS_ECP_DP_CURVE25519);
    if (rc != 0)
        return GW_ERR_CRYPTO;
    size_t olen = 0;
    uint8_t buf[64];
    rc = mbedtls_ecdh_make_params(&s->ecdh, &olen, buf, sizeof buf, mbedtls_ctr_drbg_random, gw_drbg_ctx());
    if (rc != 0 || olen < SCANNER_PUB_LEN + 4)
        return GW_ERR_CRYPTO;
    /* make_params prefixes a 3-byte ECParameters header and a 1-byte length. */
    memcpy(our_pub, buf + 4, SCANNER_PUB_LEN);
    s->established = 0;
    return GW_OK;
}

int scanner_pair_finish(struct scanner_session *s, const uint8_t scanner_pub[SCANNER_PUB_LEN])
{
    uint8_t point[1 + SCANNER_PUB_LEN];
    size_t olen = 0;

    point[0] = SCANNER_PUB_LEN;
    memcpy(point + 1, scanner_pub, SCANNER_PUB_LEN);
    const uint8_t *p = point;
    if (mbedtls_ecdh_read_public(&s->ecdh, p, sizeof point) != 0)
        return GW_ERR_CRYPTO;
    if (mbedtls_ecdh_calc_secret(&s->ecdh, &olen, s->shared, sizeof s->shared, mbedtls_ctr_drbg_random,
                                 gw_drbg_ctx()) != 0)
        return GW_ERR_CRYPTO;
    s->established = 1;
    GW_LOG("ble: scanner paired");
    return GW_OK;
}

void scanner_session_free(struct scanner_session *s)
{
    mbedtls_ecdh_free(&s->ecdh);
    memset(s->shared, 0, sizeof s->shared);
    s->established = 0;
}
