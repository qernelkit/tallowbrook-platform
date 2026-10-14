/*
 * Per-depot keys are derived from the region master key and the depot number, so a depot's keys can
 * be recreated after a restore without storing one file per depot.
 */
#include <sodium.h>
#include <string.h>

#include "keyd/crypto_api.h"
#include "keyd/keyd.h"

int keyd_depot_derive_keys(struct depot *depot, const unsigned char region_master[32])
{
    unsigned char subkey[32];

    if (depot->number == 0)
        return KEYD_ERR_ARGS;
    crypto_kdf_derive_from_key(subkey, sizeof subkey, depot->number, "DEPOTKEY", region_master);
    memcpy(depot->ack_key, subkey, sizeof depot->ack_key);
    sodium_memzero(subkey, sizeof subkey);
    return KEYD_OK;
}
