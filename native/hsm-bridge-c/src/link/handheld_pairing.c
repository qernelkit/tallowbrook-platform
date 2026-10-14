/*
 * Courier handhelds pair with tbkeyd through the courier app's enrolment screen: the handheld
 * sends its public key, both sides compute the session keys, and the courier id is bound to them
 * until the handheld is wiped or re-enrolled.
 */
#include <sodium.h>
#include <stdio.h>
#include <string.h>

#include "keyd/keyd.h"
#include "keyd/link.h"
#include "util/log.h"

static unsigned char server_pk[crypto_kx_PUBLICKEYBYTES];
static unsigned char server_sk[crypto_kx_SECRETKEYBYTES];
static int server_ready;

int keyd_handheld_init(void)
{
    if (sodium_init() < 0)
        return KEYD_ERR_LIB;
    crypto_kx_keypair(server_pk, server_sk);
    server_ready = 1;
    return KEYD_OK;
}

int keyd_handheld_server_public(unsigned char out[KEYD_HANDHELD_PUB_LEN])
{
    if (!server_ready)
        return KEYD_ERR_ARGS;
    memcpy(out, server_pk, KEYD_HANDHELD_PUB_LEN);
    return KEYD_OK;
}

static int valid_courier_id(const char *id)
{
    size_t n = strlen(id);
    if (n < 4 || n >= sizeof((struct keyd_handheld *)0)->courier_id)
        return 0;
    return strncmp(id, "CR-", 3) == 0;
}

int keyd_handheld_pair(const char *courier_id, const unsigned char handheld_pk[KEYD_HANDHELD_PUB_LEN],
                       struct keyd_handheld *out)
{
    unsigned char rx[crypto_kx_SESSIONKEYBYTES], tx[crypto_kx_SESSIONKEYBYTES];

    if (!server_ready || !valid_courier_id(courier_id))
        return KEYD_ERR_ARGS;
    if (crypto_kx_server_session_keys(rx, tx, server_pk, server_sk, handheld_pk) != 0) {
        log_warn("handheld: key from %s rejected", courier_id);
        return KEYD_ERR_ARGS;
    }
    memset(out, 0, sizeof *out);
    snprintf(out->courier_id, sizeof out->courier_id, "%s", courier_id);
    memcpy(out->rx, rx, sizeof out->rx);
    memcpy(out->tx, tx, sizeof out->tx);
    sodium_memzero(rx, sizeof rx);
    sodium_memzero(tx, sizeof tx);
    log_info("handheld: %s enrolled", courier_id);
    return KEYD_OK;
}
