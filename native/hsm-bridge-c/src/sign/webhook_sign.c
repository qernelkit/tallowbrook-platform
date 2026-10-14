/*
 * Partner webhooks (shipment events to retailers). Each partner has its own signing key; the
 * signature covers the timestamp and the body, and goes into the Tallowbrook-Signature header as
 * "t=<unix time>,v1=<hex>".
 */
#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>

#include "keyd/crypto_api.h"
#include "keyd/keyd.h"
#include "util/crypto_util.h"
#include "util/log.h"

#define WEBHOOK_BODY_MAX (256u << 10)

int keyd_webhook_sign(const unsigned char seed[32], time_t ts, const char *body, size_t body_len, char *header,
                      size_t header_cap)
{
    unsigned char sig[64];
    char sig_hex[129], prefix[24];
    size_t sig_len = sizeof sig;
    unsigned char *msg = NULL;
    int rc = KEYD_ERR_LIB;

    if (body_len > WEBHOOK_BODY_MAX)
        return KEYD_ERR_ARGS;
    int plen = snprintf(prefix, sizeof prefix, "%lld.", (long long)ts);
    msg = malloc((size_t)plen + body_len);
    if (msg == NULL)
        return KEYD_ERR_NOMEM;
    memcpy(msg, prefix, (size_t)plen);
    memcpy(msg + plen, body, body_len);

    EVP_PKEY *key = EVP_PKEY_new_raw_private_key_ex(NULL, "ED25519", NULL, seed, 32);
    EVP_MD_CTX *mctx = EVP_MD_CTX_new();
    if (key == NULL || mctx == NULL)
        goto out;
    if (EVP_DigestSignInit_ex(mctx, NULL, NULL, NULL, NULL, key, NULL) != 1)
        goto out;
    if (EVP_DigestSign(mctx, sig, &sig_len, msg, (size_t)plen + body_len) != 1)
        goto out;
    crypto_hex_encode(sig_hex, sizeof sig_hex, sig, sig_len);
    if (snprintf(header, header_cap, "t=%lld,v1=%s", (long long)ts, sig_hex) >= (int)header_cap) {
        rc = KEYD_ERR_ARGS;
        goto out;
    }
    rc = KEYD_OK;
out:
    if (rc == KEYD_ERR_LIB)
        log_openssl_errors("webhook: signing");
    EVP_MD_CTX_free(mctx);
    EVP_PKEY_free(key);
    free(msg);
    return rc;
}
