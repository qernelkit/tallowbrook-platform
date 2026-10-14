/*
 * Depot enrolment tokens. A new gateway is enrolled by a technician who types the token from the
 * enrolment screen; the cloud enrolment service checks it with the same key. The token is a compact
 * JWS so the service can use its existing JWT library.
 */
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "keyd/crypto_api.h"
#include "keyd/keyd.h"
#include "util/log.h"

#define TOKEN_LIFETIME_S (72 * 3600)

static const char TOKEN_HEADER[] = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
static const char B64URL[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

static size_t b64url_encode(char *out, const void *in, size_t len)
{
    const unsigned char *p = in;
    size_t n = 0, i = 0;

    for (; i + 2 < len; i += 3) {
        unsigned int v = (unsigned int)p[i] << 16 | (unsigned int)p[i + 1] << 8 | p[i + 2];
        out[n++] = B64URL[(v >> 18) & 63];
        out[n++] = B64URL[(v >> 12) & 63];
        out[n++] = B64URL[(v >> 6) & 63];
        out[n++] = B64URL[v & 63];
    }
    if (len - i == 1) {
        unsigned int v = (unsigned int)p[i] << 16;
        out[n++] = B64URL[(v >> 18) & 63];
        out[n++] = B64URL[(v >> 12) & 63];
    } else if (len - i == 2) {
        unsigned int v = (unsigned int)p[i] << 16 | (unsigned int)p[i + 1] << 8;
        out[n++] = B64URL[(v >> 18) & 63];
        out[n++] = B64URL[(v >> 12) & 63];
        out[n++] = B64URL[(v >> 6) & 63];
    }
    out[n] = '\0';
    return n;
}

static size_t b64url_len(size_t len)
{
    return (len * 4 + 2) / 3;
}

int keyd_enrol_token_issue(const struct depot *depot, const unsigned char *key, size_t key_len, time_t now,
                           char *token, size_t token_cap)
{
    char claims[192];
    unsigned char mac[EVP_MAX_MD_SIZE];
    unsigned int mac_len = 0;

    int clen = snprintf(claims, sizeof claims,
                        "{\"sub\":\"depot-%s\",\"aud\":\"gw-enrol\",\"iat\":%lld,\"exp\":%lld,\"region\":\"%s\"}",
                        depot->code, (long long)now, (long long)(now + TOKEN_LIFETIME_S), depot->region);
    if (clen < 0 || (size_t)clen >= sizeof claims)
        return KEYD_ERR_ARGS;
    size_t need = b64url_len(strlen(TOKEN_HEADER)) + 1 + b64url_len((size_t)clen) + 1 + b64url_len(32) + 1;
    if (token_cap < need)
        return KEYD_ERR_ARGS;

    size_t n = b64url_encode(token, TOKEN_HEADER, strlen(TOKEN_HEADER));
    token[n++] = '.';
    n += b64url_encode(token + n, claims, (size_t)clen);
    const unsigned char *signing_input = (const unsigned char *)token;
    size_t input_len = n;
    token[n++] = '.';
    if (HMAC(EVP_sha256(), key, (int)key_len, signing_input, input_len, mac, &mac_len) == NULL)
        return KEYD_ERR_LIB;
    n += b64url_encode(token + n, mac, mac_len);

    log_info("enrol: token issued for depot %s, valid %d h", depot->code, TOKEN_LIFETIME_S / 3600);
    return KEYD_OK;
}
