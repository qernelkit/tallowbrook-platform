/*
 * Yard barrier commands. The barrier controllers accept a command only with a valid tag and a counter
 * higher than the last one they executed. Each barrier has its own key, provisioned at installation.
 *
 * Command: gate (8) | action (1) | counter (4, big endian) | tag (16).
 */
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <string.h>

#include "keyd/crypto_api.h"
#include "keyd/keyd.h"
#include "util/log.h"

#define BARRIER_TAG_LEN 16
#define BARRIER_MSG_LEN 13

enum barrier_action { BARRIER_OPEN = 1, BARRIER_CLOSE = 2, BARRIER_HOLD = 3 };

static int barrier_tag(const unsigned char key[16], const unsigned char *msg, size_t msg_len,
                       unsigned char tag[BARRIER_TAG_LEN])
{
    EVP_MAC *cmac = EVP_MAC_fetch(NULL, "CMAC", NULL);
    EVP_MAC_CTX *ctx = cmac ? EVP_MAC_CTX_new(cmac) : NULL;
    size_t tag_len = 0;
    int rc = KEYD_ERR_LIB;

    OSSL_PARAM params[2];
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_CIPHER, (char *)"AES-128-CBC", 0);
    params[1] = OSSL_PARAM_construct_end();
    if (ctx != NULL && EVP_MAC_init(ctx, key, 16, params) == 1 && EVP_MAC_update(ctx, msg, msg_len) == 1
        && EVP_MAC_final(ctx, tag, &tag_len, BARRIER_TAG_LEN) == 1 && tag_len == BARRIER_TAG_LEN)
        rc = KEYD_OK;
    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(cmac);
    return rc;
}

int keyd_barrier_command(const unsigned char key[16], const char *gate, int action, uint32_t counter,
                         unsigned char *out, size_t out_cap, size_t *out_len)
{
    if (action < BARRIER_OPEN || action > BARRIER_HOLD || strlen(gate) == 0 || strlen(gate) > 8)
        return KEYD_ERR_ARGS;
    if (out_cap < BARRIER_MSG_LEN + BARRIER_TAG_LEN)
        return KEYD_ERR_ARGS;

    memset(out, ' ', 8);
    memcpy(out, gate, strlen(gate));
    out[8] = (unsigned char)action;
    out[9] = (unsigned char)(counter >> 24);
    out[10] = (unsigned char)(counter >> 16);
    out[11] = (unsigned char)(counter >> 8);
    out[12] = (unsigned char)counter;
    int rc = barrier_tag(key, out, BARRIER_MSG_LEN, out + BARRIER_MSG_LEN);
    if (rc != KEYD_OK) {
        log_openssl_errors("barrier: tag");
        return rc;
    }
    *out_len = BARRIER_MSG_LEN + BARRIER_TAG_LEN;
    return KEYD_OK;
}
