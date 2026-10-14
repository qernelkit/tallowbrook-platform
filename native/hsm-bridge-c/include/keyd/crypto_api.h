/*
 * Prototypes of the signing, enrolment, console and vendor modules. The request layer and the
 * operator tools that link keyd_core call these; nothing else lives in this header.
 */
#ifndef KEYD_PUBLIC_API_H
#define KEYD_PUBLIC_API_H

#include <stddef.h>
#include <stdint.h>
#include <time.h>

#include "keyd/keyd.h"

#define KEYD_EXPORT __attribute__((visibility("default")))

/* rng/drbg.c */
KEYD_EXPORT int keyd_rng_init(void);
KEYD_EXPORT int keyd_rng_bytes(unsigned char *out, size_t len);
KEYD_EXPORT unsigned long keyd_rng_calls(void);
KEYD_EXPORT void keyd_rng_free(void);

/* console/ */
KEYD_EXPORT int keyd_operator_set_password(const char *path, const char *user, const char *password);
KEYD_EXPORT int keyd_operator_login(const char *path, const char *user, const char *password);
KEYD_EXPORT int keyd_vault_store_pin(const char *path, const char *passphrase, const char *pin);
KEYD_EXPORT int keyd_vault_unlock_pin(const char *path, const char *passphrase, char *pin, size_t pin_cap);
KEYD_EXPORT int keyd_approval_sign(const char *module_path, const char *token_label, const char *pin,
                                   const unsigned char *challenge, size_t challenge_len, unsigned char *sig,
                                   size_t *sig_len);
KEYD_EXPORT int keyd_approval_challenge(const char *operation, const char *request_id, unsigned char *out,
                                        size_t out_cap, size_t *out_len);
KEYD_EXPORT int keyd_approval_record(const char *operator_name, const char *operation, const unsigned char *sig,
                                     size_t sig_len);

/* enrol/ */
KEYD_EXPORT int keyd_enrol_token_issue(const struct depot *depot, const unsigned char *key, size_t key_len,
                                       time_t now, char *token, size_t token_cap);
KEYD_EXPORT int keyd_enrol_ack(const struct depot *depot, const unsigned char *ack, size_t ack_len,
                               unsigned char tag[32]);
KEYD_EXPORT int keyd_enrol_ack_check(const struct depot *depot, const unsigned char *ack, size_t ack_len,
                                     const unsigned char tag[32]);
KEYD_EXPORT int keyd_depot_derive_keys(struct depot *depot, const unsigned char region_master[32]);

/* escrow/ */
KEYD_EXPORT int keyd_escrow_archive_key(const unsigned char archive_key[32], const char *archive_id,
                                        struct keyd_buf *out);
KEYD_EXPORT int keyd_archive_unwrap(const unsigned char *encapsulated, size_t encapsulated_len,
                                    unsigned char archive_key[32]);

/* gatepass/ */
struct gate_pass {
    char plate[16];
    char depot[8];
    uint16_t dock;
    time_t not_before;
    time_t not_after;
};
KEYD_EXPORT int keyd_gatepass_new_key(const char *dir);
KEYD_EXPORT int keyd_gatepass_issue(const struct gate_pass *gp, const char *dir, char *qr, size_t qr_cap);

/* release/ */
struct release {
    char version[24];
    unsigned char *image;
    size_t image_len;
    unsigned char *sig;
    size_t sig_len;
};
KEYD_EXPORT int keyd_release_load(const char *dir, const char *version, struct release *rel);
KEYD_EXPORT int keyd_release_check(const struct release *rel);
KEYD_EXPORT int keyd_release_chain_matches(const char *chain_text);
KEYD_EXPORT int keyd_release_root_ready(void);
KEYD_EXPORT void keyd_release_free(struct release *rel);

/* sign/ */
struct config_bundle {
    char depot[8];
    unsigned char *data;
    size_t len;
    unsigned char content_id[32];
    unsigned char sig[64];
};
struct receipt {
    char consignment[20];
    char depot[8];
    char signed_by[40];
    time_t delivered_at;
};
KEYD_EXPORT int keyd_bundle_content_id(struct config_bundle *bundle);
KEYD_EXPORT int keyd_bundle_sign(struct config_bundle *bundle, const unsigned char *signing_sk);
KEYD_EXPORT int keyd_receipt_key_load(const char *path);
KEYD_EXPORT int keyd_receipt_key_rotate(const char *path);
KEYD_EXPORT int keyd_receipt_sign(const struct receipt *r, unsigned char *sig, size_t sig_cap, size_t *sig_len);
KEYD_EXPORT void keyd_receipt_key_free(void);
KEYD_EXPORT int keyd_webhook_sign(const unsigned char seed[32], time_t ts, const char *body, size_t body_len,
                                  char *header, size_t header_cap);
KEYD_EXPORT int keyd_partner_key_create(const char *dir, const char *partner, struct keyd_buf *public_pem);

/* vendor/ and yard/ */
KEYD_EXPORT int keyd_fuelcard_encode_sale(const char *sale_line, unsigned char *out, size_t out_cap,
                                          size_t *out_len);
KEYD_EXPORT int keyd_fuelcard_decode_reply(const unsigned char *in, size_t in_len, char *auth_code,
                                           size_t code_cap);
KEYD_EXPORT int keyd_barrier_command(const unsigned char key[16], const char *gate, int action, uint32_t counter,
                                     unsigned char *out, size_t out_cap, size_t *out_len);

/* import/ */
KEYD_EXPORT int keyd_appliance_import(const unsigned char *file, size_t file_len, const char *pass,
                                      struct keyd_buf *settings);

#endif
