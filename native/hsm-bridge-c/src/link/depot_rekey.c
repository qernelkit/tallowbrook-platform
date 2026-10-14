/*
 * Gateways rotate their link key once a day. The gateway sends a fresh encapsulation key; tbkeyd
 * encapsulates against it, feeds the shared secret into the link key schedule, and replies with the
 * ciphertext so the gateway can do the same. Both sides switch keys at the next frame.
 */
#include <openssl/evp.h>
#include <string.h>
#include <time.h>

#include "keyd/algorithms.h"
#include "keyd/keyd.h"
#include "keyd/link.h"
#include "util/crypto_util.h"
#include "util/log.h"

#define REKEY_MIN_INTERVAL_S 600

static time_t last_rekey_at;
static unsigned long rekeys_done;

static int rekey_allowed(time_t now)
{
    if (last_rekey_at != 0 && now - last_rekey_at < REKEY_MIN_INTERVAL_S) {
        log_warn("rekey: refused, last rotation %lds ago", (long)(now - last_rekey_at));
        return 0;
    }
    return 1;
}

int keyd_rekey_gateway(struct keyd_link_session *s, const unsigned char *pub, size_t pub_len, unsigned char *ct,
                       size_t ct_cap, size_t *ct_len)
{
    unsigned char secret[32];
    size_t secret_len = sizeof secret;
    size_t need = 0;
    int rc = KEYD_ERR_LIB;
    time_t now = time(NULL);

    if (!rekey_allowed(now))
        return KEYD_ERR_POLICY;

    EVP_PKEY *peer = EVP_PKEY_new_raw_public_key_ex(NULL, KEYD_DEPOT_KEM, NULL, pub, pub_len);
    if (peer == NULL) {
        log_warn("rekey: gateway key rejected (%zu bytes)", pub_len);
        return KEYD_ERR_ARGS;
    }
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_pkey(NULL, peer, NULL);
    if (ctx == NULL || EVP_PKEY_encapsulate_init(ctx, NULL) <= 0)
        goto out;
    if (EVP_PKEY_encapsulate(ctx, NULL, &need, NULL, &secret_len) <= 0)
        goto out;
    if (need > ct_cap) {
        rc = KEYD_ERR_ARGS;
        goto out;
    }
    *ct_len = ct_cap;
    if (EVP_PKEY_encapsulate(ctx, ct, ct_len, secret, &secret_len) <= 0)
        goto out;

    rc = keyd_link_session_rekey(s, secret, secret_len);
    if (rc == KEYD_OK) {
        last_rekey_at = now;
        rekeys_done++;
        log_info("rekey: gateway link key rotated (%lu since start)", rekeys_done);
    }
out:
    if (rc == KEYD_ERR_LIB)
        log_openssl_errors("rekey");
    crypto_wipe(secret, sizeof secret);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(peer);
    return rc;
}
