/*
 * Enrolment acknowledgements. After a gateway has enrolled, it sends an acknowledgement (depot code,
 * gateway serial, firmware version); tbkeyd tags it with the depot's acknowledgement key so the
 * provisioning dashboard can show which acknowledgements came through the bridge.
 */
#include <sodium.h>
#include <string.h>

#include "keyd/crypto_api.h"
#include "keyd/keyd.h"
#include "util/log.h"

#define ACK_MAX 256

int keyd_enrol_ack(const struct depot *depot, const unsigned char *ack, size_t ack_len, unsigned char tag[32])
{
    if (ack_len == 0 || ack_len > ACK_MAX)
        return KEYD_ERR_ARGS;
    crypto_auth(tag, ack, ack_len, depot->ack_key);
    return KEYD_OK;
}

int keyd_enrol_ack_check(const struct depot *depot, const unsigned char *ack, size_t ack_len,
                         const unsigned char tag[32])
{
    if (ack_len == 0 || ack_len > ACK_MAX)
        return KEYD_ERR_ARGS;
    if (crypto_auth_verify(tag, ack, ack_len, depot->ack_key) != 0) {
        log_warn("enrol: acknowledgement for depot %s does not match", depot->code);
        return KEYD_ERR_AUTH;
    }
    return KEYD_OK;
}
