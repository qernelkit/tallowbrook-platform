/*
 * Sealed audit segments. The archive keeps segments for seven years and is run by another team, so a
 * segment leaves tbkeyd sealed under the audit archive key; the segment id is bound in as associated
 * data so segments cannot be swapped.
 *
 * Output: nonce (24) | ciphertext | tag (16).
 */
#include <sodium.h>
#include <string.h>

#include "keyd/audit.h"
#include "keyd/keyd.h"

int keyd_segment_seal(const struct audit_segment *seg, const unsigned char segment_key[KEYD_SEGMENT_KEY_LEN],
                      unsigned char *out, size_t out_cap, size_t *out_len)
{
    unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
    unsigned long long sealed_len = 0;

    if (seg->len > KEYD_SEGMENT_MAX)
        return KEYD_ERR_ARGS;
    if (out_cap < sizeof nonce + seg->len + crypto_aead_xchacha20poly1305_ietf_ABYTES)
        return KEYD_ERR_ARGS;
    randombytes_buf(nonce, sizeof nonce);
    memcpy(out, nonce, sizeof nonce);

    crypto_aead_xchacha20poly1305_ietf_encrypt(out + sizeof nonce, &sealed_len, seg->data, seg->len, (const unsigned char *)seg->id, strlen(seg->id), NULL, nonce, segment_key);
    *out_len = sizeof nonce + (size_t)sealed_len;
    return KEYD_OK;
}
