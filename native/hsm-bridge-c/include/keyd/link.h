/* Encrypted link to the depot gateways and the courier handhelds. */
#ifndef KEYD_LINK_H
#define KEYD_LINK_H

#include <stddef.h>
#include <stdint.h>

#include "keyd/algorithms.h"

struct keyd_link_session;

int keyd_link_init(void);
void keyd_link_shutdown(void);

struct keyd_link_session *keyd_link_session_new(int initiator);
void keyd_link_session_free(struct keyd_link_session *s);
int keyd_link_session_public(const struct keyd_link_session *s, unsigned char *out, size_t out_len);
int keyd_link_session_establish(struct keyd_link_session *s, const unsigned char *peer, size_t peer_len,
                                const unsigned char *hello, size_t hello_len);
int keyd_link_session_rekey(struct keyd_link_session *s, const unsigned char *secret, size_t secret_len);

/* Frames carry an 8-byte sequence number as associated data. */
int keyd_link_seal(struct keyd_link_session *s, const unsigned char *in, size_t in_len, unsigned char *out,
                   size_t out_cap, size_t *out_len);
int keyd_link_open(struct keyd_link_session *s, const unsigned char *in, size_t in_len, unsigned char *out,
                   size_t out_cap, size_t *out_len);

/* Key schedule and frame protection, shared with the escrow code. */
int keyd_kdf_expand(const unsigned char *ikm, size_t ikm_len, const unsigned char *salt, size_t salt_len,
                    const char *info, unsigned char *okm, size_t okm_len);
int keyd_aead_seal(const unsigned char key[KEYD_LINK_KEY_LEN], const unsigned char iv[KEYD_LINK_IV_LEN],
                   const unsigned char *aad, size_t aad_len, const unsigned char *in, size_t in_len,
                   unsigned char *out);
int keyd_aead_open(const unsigned char key[KEYD_LINK_KEY_LEN], const unsigned char iv[KEYD_LINK_IV_LEN],
                   const unsigned char *aad, size_t aad_len, const unsigned char *in, size_t in_len,
                   unsigned char *out);

/* ML-KEM rotation of a gateway's link key. */
int keyd_rekey_gateway(struct keyd_link_session *s, const unsigned char *gateway_pub, size_t pub_len,
                       unsigned char *ct, size_t ct_cap, size_t *ct_len);

/* Courier handhelds. */
#define KEYD_HANDHELD_PUB_LEN 32
#define KEYD_HANDHELD_KEY_LEN 32

struct keyd_handheld {
    char courier_id[24];
    unsigned char rx[KEYD_HANDHELD_KEY_LEN];
    unsigned char tx[KEYD_HANDHELD_KEY_LEN];
    uint64_t tx_counter;
};

int keyd_handheld_init(void);
int keyd_handheld_server_public(unsigned char out[KEYD_HANDHELD_PUB_LEN]);
int keyd_handheld_pair(const char *courier_id, const unsigned char handheld_pub[KEYD_HANDHELD_PUB_LEN],
                       struct keyd_handheld *out);
int keyd_handheld_relay(struct keyd_handheld *h, const unsigned char *msg, size_t msg_len, unsigned char *out,
                        size_t out_cap, size_t *out_len);

#endif
