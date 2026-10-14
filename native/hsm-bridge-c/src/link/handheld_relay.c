/*
 * Dispatch notices relayed to courier handhelds (route changes, depot closures, parcel holds). The
 * handhelds have no AES instructions, so frames use ChaCha20-Poly1305. Replies from couriers come
 * back through the courier API, not this path.
 *
 * Frame: counter (8, big endian) | ciphertext | tag (16).
 */
#include <openssl/evp.h>
#include <string.h>

#include "keyd/keyd.h"
#include "keyd/link.h"
#include "util/log.h"

#define RELAY_TAG_LEN 16
#define RELAY_MAX_MSG 4096

int keyd_handheld_relay(struct keyd_handheld *h, const unsigned char *msg, size_t msg_len, unsigned char *out,
                        size_t out_cap, size_t *out_len)
{
    unsigned char nonce[12] = { 0 };
    const unsigned char *relay_key = h->tx;
    int n = 0, fin = 0, rc = KEYD_ERR_LIB;

    if (msg_len > RELAY_MAX_MSG || out_cap < 8 + msg_len + RELAY_TAG_LEN)
        return KEYD_ERR_ARGS;
    uint64_t counter = h->tx_counter++;
    for (int i = 0; i < 8; i++) {
        out[i] = (unsigned char)(counter >> (56 - 8 * i));
        nonce[4 + i] = out[i];
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
        return KEYD_ERR_NOMEM;
    if (EVP_EncryptInit_ex2(ctx, EVP_chacha20_poly1305(), relay_key, nonce, NULL) != 1)
        goto out;
    if (EVP_EncryptUpdate(ctx, NULL, &n, out, 8) != 1)
        goto out;
    if (EVP_EncryptUpdate(ctx, out + 8, &n, msg, (int)msg_len) != 1)
        goto out;
    if (EVP_EncryptFinal_ex(ctx, out + 8 + n, &fin) != 1)
        goto out;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, RELAY_TAG_LEN, out + 8 + n + fin) != 1)
        goto out;
    *out_len = 8 + (size_t)n + (size_t)fin + RELAY_TAG_LEN;
    rc = KEYD_OK;
out:
    if (rc != KEYD_OK)
        log_openssl_errors("handheld: relay frame");
    EVP_CIPHER_CTX_free(ctx);
    return rc;
}
