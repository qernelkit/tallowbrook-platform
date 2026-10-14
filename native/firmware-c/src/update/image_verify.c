/*
 * Update verification. The gateway downloads an update image, checks its SHA-256 against the signed
 * manifest, and verifies the manifest signature with the update signing key embedded below (the
 * online TUF key). A failed check keeps the gateway on its current A/B slot.
 *
 * Manifest layout: image_sha256 (32) | signature of that digest.
 */
#include <mbedtls/md.h>
#include <mbedtls/pk.h>
#include <mbedtls/sha256.h>
#include <string.h>

#include "gateway/gw.h"
#include "gateway/gw_config.h"
#include "gateway/gw_log.h"

static const char UPDATE_SIGNING_KEY_PEM[] =
    "-----BEGIN PUBLIC KEY-----\n"
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEJuH/eu7BqdoT8VGyLkO+wtpK1rpe\n"
    "uzT3zVA1tyTdlg8h0FnsfhxZH83/eEpj9J3/IU90/SPIgsqdZrdATGF1EA==\n"
    "-----END PUBLIC KEY-----\n";

struct update_manifest {
    uint8_t image_sha256[32];
    uint8_t signature[72];
    size_t signature_len;
    uint32_t build;
};

static mbedtls_pk_context update_key;
static int update_key_ready;

static int load_update_key(void)
{
    if (update_key_ready)
        return GW_OK;
    mbedtls_pk_init(&update_key);
    int rc = mbedtls_pk_parse_public_key(&update_key, (const unsigned char *)UPDATE_SIGNING_KEY_PEM,
                                         sizeof UPDATE_SIGNING_KEY_PEM);
    if (rc != 0) {
        GW_LOG_ERR("update: embedded key parse failed (-0x%04x)", (unsigned)-rc);
        return GW_ERR_CRYPTO;
    }
    update_key_ready = 1;
    return GW_OK;
}

static int image_digest(const uint8_t *image, size_t image_len, uint8_t digest[32])
{
    int rc = mbedtls_sha256(image, image_len, digest, 0);
    return rc == 0 ? GW_OK : GW_ERR_CRYPTO;
}

int gw_update_verify(const uint8_t *image, size_t image_len, const struct update_manifest *manifest,
                     char active_slot)
{
    uint8_t digest[32];

    if (image_len == 0 || image_len > GW_MAX_IMAGE)
        return GW_ERR_ARG;
    if (load_update_key() != GW_OK)
        return GW_ERR_CRYPTO;
    if (image_digest(image, image_len, digest) != GW_OK)
        return GW_ERR_CRYPTO;
    if (memcmp(digest, manifest->image_sha256, sizeof digest) != 0) {
        GW_LOG_WARN("update %u: image digest does not match the manifest", manifest->build);
        return GW_ERR_AUTH;
    }

    int rc = mbedtls_pk_verify_ext(MBEDTLS_PK_ECDSA, NULL, &update_key, MBEDTLS_MD_SHA256, digest, sizeof digest,
                                   manifest->signature, manifest->signature_len);
    if (rc != 0) {
        GW_LOG_WARN("update %u: signature mismatch, staying on slot %c", manifest->build, active_slot);
        return GW_ERR_AUTH;
    }
    GW_LOG("update %u: verified, ready to stage on the spare slot", manifest->build);
    return GW_OK;
}

int gw_update_parse_manifest(const uint8_t *blob, size_t len, struct update_manifest *out)
{
    if (len < sizeof out->image_sha256 + 8 || len > sizeof out->image_sha256 + sizeof out->signature)
        return GW_ERR_ARG;
    memset(out, 0, sizeof *out);
    memcpy(out->image_sha256, blob, sizeof out->image_sha256);
    out->signature_len = len - sizeof out->image_sha256;
    memcpy(out->signature, blob + sizeof out->image_sha256, out->signature_len);
    return GW_OK;
}

void gw_update_free(void)
{
    if (update_key_ready)
        mbedtls_pk_free(&update_key);
    update_key_ready = 0;
}
