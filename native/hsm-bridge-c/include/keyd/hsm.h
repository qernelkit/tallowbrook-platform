/* PKCS#11 session handling and the long-lived objects tbkeyd keeps in the HSM partition. */
#ifndef KEYD_TOKEN_H
#define KEYD_TOKEN_H

#include <p11-kit/pkcs11.h>
#include <stddef.h>

#define KEYD_ROOT_LABEL "tbk-root-2026"
#define KEYD_SETTLEMENT_LABEL "tbk-settlement-2026"
#define KEYD_KEK_LABEL "tbk-data-kek-2026"

struct keyd_table;

struct keyd_p11 {
    CK_FUNCTION_LIST_PTR fn;
    struct keyd_table *handles;
    CK_SLOT_ID slot;
    CK_SESSION_HANDLE session;
    int initialised;
    int logged_in;
};

int keyd_p11_open(struct keyd_p11 *p, const char *module_path, const char *slot_label);
int keyd_p11_login(struct keyd_p11 *p, const char *pin, size_t pin_len);
void keyd_p11_close(struct keyd_p11 *p);
int keyd_p11_find(struct keyd_p11 *p, CK_OBJECT_CLASS cls, const char *label, CK_OBJECT_HANDLE *out);

int keyd_p11_create_root(struct keyd_p11 *p, CK_OBJECT_HANDLE *pub, CK_OBJECT_HANDLE *priv);
int keyd_p11_create_settlement_key(struct keyd_p11 *p, CK_OBJECT_HANDLE *pub, CK_OBJECT_HANDLE *priv);
int keyd_p11_create_kek(struct keyd_p11 *p, CK_OBJECT_HANDLE *kek);
int keyd_p11_ensure_objects(struct keyd_p11 *p);

int keyd_p11_wrap_data_key(struct keyd_p11 *p, const char *data_key_label, unsigned char *out, size_t *out_len);
int keyd_p11_seal(struct keyd_p11 *p, const char *key_label, const unsigned char *iv, size_t iv_len,
                  const unsigned char *aad, size_t aad_len, const unsigned char *in, size_t in_len,
                  unsigned char *out, size_t *out_len);
int keyd_p11_sign_settlement(struct keyd_p11 *p, const unsigned char *file, size_t file_len, unsigned char *sig,
                             size_t *sig_len);

#endif
