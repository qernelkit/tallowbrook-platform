/*
 * Telemetry records are batched and sealed before they leave the gateway, so a captured uplink
 * cannot read depot sensor history even before the TLS layer. The telemetry key is derived on the
 * collector side from the device identity at enrolment.
 */
#include <mbedtls/gcm.h>
#include <string.h>

#include "gateway/gw.h"
#include "gateway/telemetry.h"

#define TELEMETRY_IV_LEN 12
#define TELEMETRY_TAG_LEN 16

int telemetry_seal(const uint8_t telemetry_key[32], const uint8_t *records, size_t len, const uint8_t *iv,
                   uint8_t *out, size_t out_cap, size_t *out_len)
{
    mbedtls_gcm_context gcm;
    int rc;

    if (out_cap < TELEMETRY_IV_LEN + len + TELEMETRY_TAG_LEN)
        return GW_ERR_ARG;
    mbedtls_gcm_init(&gcm);
    rc = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, telemetry_key, 256);
    if (rc == 0) {
        memcpy(out, iv, TELEMETRY_IV_LEN);
        rc = mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, len, iv, TELEMETRY_IV_LEN, NULL, 0, records,
                                       out + TELEMETRY_IV_LEN, TELEMETRY_TAG_LEN, out + TELEMETRY_IV_LEN + len);
    }
    mbedtls_gcm_free(&gcm);
    if (rc != 0)
        return GW_ERR_CRYPTO;
    *out_len = TELEMETRY_IV_LEN + len + TELEMETRY_TAG_LEN;
    return GW_OK;
}
