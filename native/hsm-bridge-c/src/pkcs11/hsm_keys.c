/*
 * Long-lived objects in the partition: the root signing key, the partner-settlement signing key and
 * the data-key wrapping key (KEK). Each is created once, on the first start after the partition is
 * initialised; later starts find it by label.
 */
#include "keyd/hsm.h"

#include <string.h>

#include "keyd/keyd.h"
#include "util/log.h"

/* DER of the secp384r1 OID, the CKA_EC_PARAMS value for the root key pair. */
static const CK_BYTE SECP384R1_OID[] = { 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22 };

static CK_BBOOL yes = CK_TRUE;
static CK_BBOOL no = CK_FALSE;

static int generated(const char *what, CK_RV rv)
{
    if (rv != CKR_OK) {
        log_err("token: creating %s failed (rv=0x%lx)", what, (unsigned long)rv);
        return KEYD_ERR_TOKEN;
    }
    log_info("token: created %s", what);
    return KEYD_OK;
}

int keyd_p11_create_root(struct keyd_p11 *p, CK_OBJECT_HANDLE *pub, CK_OBJECT_HANDLE *priv)
{
    CK_MECHANISM ec_gen = { CKM_EC_KEY_PAIR_GEN, NULL_PTR, 0 };
    CK_UTF8CHAR label[] = KEYD_ROOT_LABEL;
    CK_ATTRIBUTE pub_tmpl[] = {
        { CKA_TOKEN, &yes, sizeof yes },
        { CKA_LABEL, label, sizeof label - 1 },
        { CKA_EC_PARAMS, (CK_VOID_PTR)SECP384R1_OID, sizeof SECP384R1_OID },
        { CKA_VERIFY, &yes, sizeof yes },
    };
    CK_ATTRIBUTE priv_tmpl[] = {
        { CKA_TOKEN, &yes, sizeof yes },
        { CKA_PRIVATE, &yes, sizeof yes },
        { CKA_SENSITIVE, &yes, sizeof yes },
        { CKA_EXTRACTABLE, &no, sizeof no },
        { CKA_LABEL, label, sizeof label - 1 },
        { CKA_SIGN, &yes, sizeof yes },
    };

    CK_RV rv = p->fn->C_GenerateKeyPair(p->session, &ec_gen, pub_tmpl, 4, priv_tmpl, 6, pub, priv);
    return generated("the root signing key", rv);
}

int keyd_p11_create_settlement_key(struct keyd_p11 *p, CK_OBJECT_HANDLE *pub, CK_OBJECT_HANDLE *priv)
{
    CK_MECHANISM rsa_gen = { CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0 };
    CK_ULONG modulus_bits = 3072;
    CK_BYTE public_exponent[] = { 0x01, 0x00, 0x01 };
    CK_UTF8CHAR label[] = KEYD_SETTLEMENT_LABEL;
    CK_ATTRIBUTE pub_tmpl[] = {
        { CKA_TOKEN, &yes, sizeof yes },
        { CKA_LABEL, label, sizeof label - 1 },
        { CKA_MODULUS_BITS, &modulus_bits, sizeof modulus_bits },
        { CKA_PUBLIC_EXPONENT, public_exponent, sizeof public_exponent },
        { CKA_VERIFY, &yes, sizeof yes },
    };
    CK_ATTRIBUTE priv_tmpl[] = {
        { CKA_TOKEN, &yes, sizeof yes },
        { CKA_PRIVATE, &yes, sizeof yes },
        { CKA_SENSITIVE, &yes, sizeof yes },
        { CKA_EXTRACTABLE, &no, sizeof no },
        { CKA_LABEL, label, sizeof label - 1 },
        { CKA_SIGN, &yes, sizeof yes },
    };

    CK_RV rv = p->fn->C_GenerateKeyPair(p->session, &rsa_gen, pub_tmpl, 5, priv_tmpl, 6, pub, priv);
    return generated("the settlement signing key", rv);
}

int keyd_p11_create_kek(struct keyd_p11 *p, CK_OBJECT_HANDLE *kek)
{
    CK_MECHANISM kek_gen = { CKM_AES_KEY_GEN, NULL_PTR, 0 };
    CK_ULONG kek_len = 32;
    CK_UTF8CHAR label[] = KEYD_KEK_LABEL;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_TOKEN, &yes, sizeof yes },
        { CKA_LABEL, label, sizeof label - 1 },
        { CKA_VALUE_LEN, &kek_len, sizeof kek_len },
        { CKA_WRAP, &yes, sizeof yes },
        { CKA_UNWRAP, &yes, sizeof yes },
        { CKA_SENSITIVE, &yes, sizeof yes },
        { CKA_EXTRACTABLE, &no, sizeof no },
    };

    CK_RV rv = p->fn->C_GenerateKey(p->session, &kek_gen, tmpl, 7, kek);
    return generated("the data-key wrapping key", rv);
}

/* Called at start-up with a logged-in session. */
int keyd_p11_ensure_objects(struct keyd_p11 *p)
{
    CK_OBJECT_HANDLE pub, priv, kek;
    int rc;

    rc = keyd_p11_find(p, CKO_PRIVATE_KEY, KEYD_ROOT_LABEL, &priv);
    if (rc == KEYD_ERR_NOTFOUND)
        rc = keyd_p11_create_root(p, &pub, &priv);
    if (rc != KEYD_OK)
        return rc;

    rc = keyd_p11_find(p, CKO_PRIVATE_KEY, KEYD_SETTLEMENT_LABEL, &priv);
    if (rc == KEYD_ERR_NOTFOUND)
        rc = keyd_p11_create_settlement_key(p, &pub, &priv);
    if (rc != KEYD_OK)
        return rc;

    rc = keyd_p11_find(p, CKO_SECRET_KEY, KEYD_KEK_LABEL, &kek);
    if (rc == KEYD_ERR_NOTFOUND)
        rc = keyd_p11_create_kek(p, &kek);
    return rc;
}
