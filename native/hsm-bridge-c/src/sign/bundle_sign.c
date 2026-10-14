/*
 * Depot configuration bundles (barrier schedules, fuel prices, dock assignments) are content
 * addressed and signed; gateways refuse a bundle whose signature does not check out against the key
 * from their enrolment.
 */
#include <sodium.h>
#include <string.h>

#include "keyd/crypto_api.h"
#include "keyd/keyd.h"
#include "util/log.h"

#define BUNDLE_MAX (4u << 20)

int keyd_bundle_content_id(struct config_bundle *bundle)
{
    if (bundle->len == 0 || bundle->len > BUNDLE_MAX)
        return KEYD_ERR_ARGS;
    crypto_generichash(bundle->content_id, 32, bundle->data, bundle->len, NULL, 0);
    return KEYD_OK;
}

int keyd_bundle_sign(struct config_bundle *bundle, const unsigned char *signing_sk)
{
    int rc = keyd_bundle_content_id(bundle);
    if (rc != KEYD_OK)
        return rc;
    crypto_sign_ed25519_detached(bundle->sig, NULL, bundle->data, bundle->len, signing_sk);
    log_info("bundle: signed %zu bytes for depot %s", bundle->len, bundle->depot);
    return KEYD_OK;
}
