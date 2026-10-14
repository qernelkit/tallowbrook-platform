/*
 * The depot link: each gateway keeps one long-lived connection to tbkeyd. A session starts with an
 * ephemeral key exchange and the two hello randoms, the key schedule turns the shared secret into
 * one key and IV prefix per direction, and every frame is sealed with its sequence number as
 * associated data. The escrow code uses the same key schedule and frame protection.
 */
#include "keyd/link.h"

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <stdlib.h>
#include <string.h>

#include "keyd/keyd.h"
#include "util/crypto_util.h"
#include "util/log.h"

#define LINK_PUB_LEN 32
#define LINK_SEQ_LEN 8
#define LINK_OKM_LEN (2 * KEYD_LINK_KEY_LEN + 2 * KEYD_LINK_IV_LEN)

static const char LINK_INFO[] = "tbk depot link v2";
static const char REKEY_INFO[] = "tbk depot link rekey";

struct keyd_link_session {
    EVP_PKEY *ephemeral;
    int initiator;
    int established;
    unsigned char hello[2 * KEYD_LINK_HELLO_LEN];
    unsigned char tx_key[KEYD_LINK_KEY_LEN];
    unsigned char rx_key[KEYD_LINK_KEY_LEN];
    unsigned char tx_iv[KEYD_LINK_IV_LEN];
    unsigned char rx_iv[KEYD_LINK_IV_LEN];
    uint64_t tx_seq;
    uint64_t rx_seq;
};

static EVP_CIPHER *link_aead;
static EVP_KDF *link_kdf;

int keyd_link_init(void)
{
    EVP_CIPHER *aead = EVP_CIPHER_fetch(NULL, "AES-256-GCM", NULL);
    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);

    if (aead == NULL || kdf == NULL) {
        log_openssl_errors("link: algorithm fetch");
        EVP_CIPHER_free(aead);
        EVP_KDF_free(kdf);
        return KEYD_ERR_LIB;
    }
    link_aead = aead;
    link_kdf = kdf;
    return KEYD_OK;
}

void keyd_link_shutdown(void)
{
    EVP_CIPHER_free(link_aead);
    EVP_KDF_free(link_kdf);
    link_aead = NULL;
    link_kdf = NULL;
}

int keyd_kdf_expand(const unsigned char *ikm, size_t ikm_len, const unsigned char *salt, size_t salt_len,
                    const char *info, unsigned char *okm, size_t okm_len)
{
    EVP_KDF_CTX *kctx = EVP_KDF_CTX_new(link_kdf);
    if (kctx == NULL)
        return KEYD_ERR_LIB;

    OSSL_PARAM params[5], *p = params;
    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, (char *)KEYD_LINK_KDF_DIGEST, 0);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, (void *)ikm, ikm_len);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, (void *)salt, salt_len);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, (void *)info, strlen(info));
    *p = OSSL_PARAM_construct_end();

    int ok = EVP_KDF_derive(kctx, okm, okm_len, params) == 1;
    EVP_KDF_CTX_free(kctx);
    if (!ok) {
        log_openssl_errors("link: key schedule");
        return KEYD_ERR_LIB;
    }
    return KEYD_OK;
}

int keyd_aead_seal(const unsigned char key[KEYD_LINK_KEY_LEN], const unsigned char iv[KEYD_LINK_IV_LEN],
                   const unsigned char *aad, size_t aad_len, const unsigned char *in, size_t in_len,
                   unsigned char *out)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int n = 0, fin = 0, rc = KEYD_ERR_LIB;

    if (ctx == NULL || in_len > INT32_MAX || aad_len > INT32_MAX)
        goto out;
    if (EVP_EncryptInit_ex2(ctx, link_aead, key, iv, NULL) != 1)
        goto out;
    if (aad_len > 0 && EVP_EncryptUpdate(ctx, NULL, &n, aad, (int)aad_len) != 1)
        goto out;
    if (EVP_EncryptUpdate(ctx, out, &n, in, (int)in_len) != 1)
        goto out;
    if (EVP_EncryptFinal_ex(ctx, out + n, &fin) != 1)
        goto out;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, KEYD_LINK_TAG_LEN, out + n + fin) != 1)
        goto out;
    rc = KEYD_OK;
out:
    EVP_CIPHER_CTX_free(ctx);
    return rc;
}

int keyd_aead_open(const unsigned char key[KEYD_LINK_KEY_LEN], const unsigned char iv[KEYD_LINK_IV_LEN],
                   const unsigned char *aad, size_t aad_len, const unsigned char *in, size_t in_len,
                   unsigned char *out)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int n = 0, fin = 0, rc = KEYD_ERR_LIB;

    if (ctx == NULL || in_len < KEYD_LINK_TAG_LEN || in_len > INT32_MAX || aad_len > INT32_MAX)
        goto out;
    size_t body = in_len - KEYD_LINK_TAG_LEN;
    if (EVP_DecryptInit_ex2(ctx, link_aead, key, iv, NULL) != 1)
        goto out;
    if (aad_len > 0 && EVP_DecryptUpdate(ctx, NULL, &n, aad, (int)aad_len) != 1)
        goto out;
    if (EVP_DecryptUpdate(ctx, out, &n, in, (int)body) != 1)
        goto out;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, KEYD_LINK_TAG_LEN, (void *)(in + body)) != 1)
        goto out;
    rc = EVP_DecryptFinal_ex(ctx, out + n, &fin) == 1 ? KEYD_OK : KEYD_ERR_AUTH;
out:
    EVP_CIPHER_CTX_free(ctx);
    return rc;
}

struct keyd_link_session *keyd_link_session_new(int initiator)
{
    struct keyd_link_session *s = calloc(1, sizeof *s);
    if (s == NULL)
        return NULL;
    s->initiator = initiator;

    EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_from_name(NULL, "X25519", NULL);
    if (kctx == NULL || EVP_PKEY_keygen_init(kctx) <= 0 || EVP_PKEY_generate(kctx, &s->ephemeral) <= 0) {
        log_openssl_errors("link: ephemeral key");
        EVP_PKEY_CTX_free(kctx);
        free(s);
        return NULL;
    }
    EVP_PKEY_CTX_free(kctx);
    return s;
}

void keyd_link_session_free(struct keyd_link_session *s)
{
    if (s == NULL)
        return;
    EVP_PKEY_free(s->ephemeral);
    crypto_wipe(s, sizeof *s);
    free(s);
}

int keyd_link_session_public(const struct keyd_link_session *s, unsigned char *out, size_t out_len)
{
    size_t len = out_len;
    if (out_len < LINK_PUB_LEN || EVP_PKEY_get_raw_public_key(s->ephemeral, out, &len) != 1)
        return KEYD_ERR_ARGS;
    return KEYD_OK;
}

static void assign_directions(struct keyd_link_session *s, const unsigned char *okm)
{
    const unsigned char *i2r_key = okm;
    const unsigned char *r2i_key = okm + KEYD_LINK_KEY_LEN;
    const unsigned char *i2r_iv = okm + 2 * KEYD_LINK_KEY_LEN;
    const unsigned char *r2i_iv = i2r_iv + KEYD_LINK_IV_LEN;

    memcpy(s->tx_key, s->initiator ? i2r_key : r2i_key, KEYD_LINK_KEY_LEN);
    memcpy(s->rx_key, s->initiator ? r2i_key : i2r_key, KEYD_LINK_KEY_LEN);
    memcpy(s->tx_iv, s->initiator ? i2r_iv : r2i_iv, KEYD_LINK_IV_LEN);
    memcpy(s->rx_iv, s->initiator ? r2i_iv : i2r_iv, KEYD_LINK_IV_LEN);
    s->tx_seq = 0;
    s->rx_seq = 0;
}

int keyd_link_session_establish(struct keyd_link_session *s, const unsigned char *peer, size_t peer_len,
                                const unsigned char *hello, size_t hello_len)
{
    unsigned char shared[32], okm[LINK_OKM_LEN];
    size_t shared_len = sizeof shared;
    int rc = KEYD_ERR_LIB;

    if (peer_len != LINK_PUB_LEN || hello_len != sizeof s->hello)
        return KEYD_ERR_ARGS;
    EVP_PKEY *their = EVP_PKEY_new_raw_public_key_ex(NULL, EVP_PKEY_get0_type_name(s->ephemeral), NULL, peer, peer_len);
    EVP_PKEY_CTX *dctx = EVP_PKEY_CTX_new_from_pkey(NULL, s->ephemeral, NULL);
    if (their == NULL || dctx == NULL)
        goto out;
    if (EVP_PKEY_derive_init(dctx) <= 0 || EVP_PKEY_derive_set_peer(dctx, their) <= 0)
        goto out;
    if (EVP_PKEY_derive(dctx, shared, &shared_len) <= 0)
        goto out;

    memcpy(s->hello, hello, hello_len);
    rc = keyd_kdf_expand(shared, shared_len, s->hello, sizeof s->hello, LINK_INFO, okm, sizeof okm);
    if (rc == KEYD_OK) {
        assign_directions(s, okm);
        s->established = 1;
    }
out:
    if (rc != KEYD_OK)
        log_openssl_errors("link: session set-up");
    crypto_wipe(shared, sizeof shared);
    crypto_wipe(okm, sizeof okm);
    EVP_PKEY_CTX_free(dctx);
    EVP_PKEY_free(their);
    return rc;
}

int keyd_link_session_rekey(struct keyd_link_session *s, const unsigned char *secret, size_t secret_len)
{
    unsigned char okm[LINK_OKM_LEN];
    if (!s->established)
        return KEYD_ERR_ARGS;
    int rc = keyd_kdf_expand(secret, secret_len, s->hello, sizeof s->hello, REKEY_INFO, okm, sizeof okm);
    if (rc == KEYD_OK)
        assign_directions(s, okm);
    crypto_wipe(okm, sizeof okm);
    return rc;
}

static void put_be64(unsigned char *p, uint64_t v)
{
    for (int i = 7; i >= 0; i--) {
        p[i] = (unsigned char)v;
        v >>= 8;
    }
}

static uint64_t get_be64(const unsigned char *p)
{
    uint64_t v = 0;
    for (int i = 0; i < 8; i++)
        v = v << 8 | p[i];
    return v;
}

/* Per-frame IV: the direction's prefix with the sequence number XORed into the last 8 bytes. */
static void frame_iv(unsigned char iv[KEYD_LINK_IV_LEN], const unsigned char prefix[KEYD_LINK_IV_LEN], uint64_t seq)
{
    unsigned char be[LINK_SEQ_LEN];
    put_be64(be, seq);
    memcpy(iv, prefix, KEYD_LINK_IV_LEN);
    for (int i = 0; i < LINK_SEQ_LEN; i++)
        iv[KEYD_LINK_IV_LEN - LINK_SEQ_LEN + i] ^= be[i];
}

int keyd_link_seal(struct keyd_link_session *s, const unsigned char *in, size_t in_len, unsigned char *out,
                   size_t out_cap, size_t *out_len)
{
    unsigned char iv[KEYD_LINK_IV_LEN];
    size_t need = LINK_SEQ_LEN + in_len + KEYD_LINK_TAG_LEN;

    if (!s->established || out_cap < need)
        return KEYD_ERR_ARGS;
    if (s->tx_seq == UINT64_MAX)
        return KEYD_ERR_POLICY;
    put_be64(out, s->tx_seq);
    frame_iv(iv, s->tx_iv, s->tx_seq);
    int rc = keyd_aead_seal(s->tx_key, iv, out, LINK_SEQ_LEN, in, in_len, out + LINK_SEQ_LEN);
    if (rc != KEYD_OK)
        return rc;
    s->tx_seq++;
    *out_len = need;
    return KEYD_OK;
}

int keyd_link_open(struct keyd_link_session *s, const unsigned char *in, size_t in_len, unsigned char *out,
                   size_t out_cap, size_t *out_len)
{
    unsigned char iv[KEYD_LINK_IV_LEN];

    if (!s->established || in_len < LINK_SEQ_LEN + KEYD_LINK_TAG_LEN)
        return KEYD_ERR_ARGS;
    size_t body = in_len - LINK_SEQ_LEN - KEYD_LINK_TAG_LEN;
    if (out_cap < body)
        return KEYD_ERR_ARGS;
    uint64_t seq = get_be64(in);
    if (seq < s->rx_seq) {
        log_warn("link: replayed frame %llu (expected >= %llu)", (unsigned long long)seq,
                 (unsigned long long)s->rx_seq);
        return KEYD_ERR_POLICY;
    }
    frame_iv(iv, s->rx_iv, seq);
    int rc = keyd_aead_open(s->rx_key, iv, in, LINK_SEQ_LEN, in + LINK_SEQ_LEN, in_len - LINK_SEQ_LEN, out);
    if (rc != KEYD_OK)
        return rc;
    s->rx_seq = seq + 1;
    *out_len = body;
    return KEYD_OK;
}
