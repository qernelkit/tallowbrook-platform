/*
 * Operations inside the HSM: handing out a data key wrapped under the KEK, sealing small blobs for
 * other services, and signing partner settlement files.
 */
#include "keyd/hsm.h"
#include "keyd/hsm_policy.h"

#include <string.h>

#include "keyd/keyd.h"
#include "util/log.h"

static int object(struct keyd_p11 *p, CK_OBJECT_CLASS cls, const char *label, CK_OBJECT_HANDLE *h)
{
    int rc = keyd_p11_find(p, cls, label, h);
    if (rc == KEYD_ERR_NOTFOUND)
        log_warn("token: no object labelled '%s'", label);
    return rc;
}

/*
 * Data keys are created by the HSM administrators' tooling, one per tenant store. A service that is
 * allowed to hold one receives it wrapped, and unwraps it in its own partition.
 */
int keyd_p11_wrap_data_key(struct keyd_p11 *p, const char *data_key_label, unsigned char *out, size_t *out_len)
{
    CK_OBJECT_HANDLE kek, data_key;
    int rc;

    if ((rc = object(p, CKO_SECRET_KEY, KEYD_KEK_LABEL, &kek)) != KEYD_OK)
        return rc;
    if ((rc = object(p, CKO_SECRET_KEY, data_key_label, &data_key)) != KEYD_OK)
        return rc;

    CK_MECHANISM wrap = { KEYD_WRAP_MECHANISM, NULL_PTR, 0 };
    CK_ULONG len = (CK_ULONG)*out_len;
    CK_RV rv = p->fn->C_WrapKey(p->session, &wrap, kek, data_key, out, &len);
    if (rv != CKR_OK) {
        log_err("token: wrapping '%s' failed (rv=0x%lx)", data_key_label, (unsigned long)rv);
        return rv == CKR_BUFFER_TOO_SMALL ? KEYD_ERR_ARGS : KEYD_ERR_TOKEN;
    }
    *out_len = len;
    return KEYD_OK;
}

int keyd_p11_seal(struct keyd_p11 *p, const char *key_label, const unsigned char *iv, size_t iv_len,
                  const unsigned char *aad, size_t aad_len, const unsigned char *in, size_t in_len,
                  unsigned char *out, size_t *out_len)
{
    CK_OBJECT_HANDLE key;
    int rc = object(p, CKO_SECRET_KEY, key_label, &key);
    if (rc != KEYD_OK)
        return rc;

    CK_GCM_PARAMS gcm_params;
    memset(&gcm_params, 0, sizeof gcm_params);
    gcm_params.pIv = (CK_BYTE_PTR)iv;
    gcm_params.ulIvLen = iv_len;
    gcm_params.ulIvBits = iv_len * 8;
    gcm_params.pAAD = (CK_BYTE_PTR)aad;
    gcm_params.ulAADLen = aad_len;
    gcm_params.ulTagBits = 128;
    CK_MECHANISM gcm = { CKM_AES_GCM, &gcm_params, sizeof gcm_params };

    CK_RV rv = p->fn->C_EncryptInit(p->session, &gcm, key);
    if (rv != CKR_OK) {
        log_err("token: seal with '%s' refused (rv=0x%lx)", key_label, (unsigned long)rv);
        return KEYD_ERR_TOKEN;
    }
    CK_ULONG len = (CK_ULONG)*out_len;
    rv = p->fn->C_Encrypt(p->session, (CK_BYTE_PTR)in, in_len, out, &len);
    if (rv != CKR_OK)
        return rv == CKR_BUFFER_TOO_SMALL ? KEYD_ERR_ARGS : KEYD_ERR_TOKEN;
    *out_len = len;
    return KEYD_OK;
}

/* Settlement files go to the partner banks, which verify against the certificate on file. */
int keyd_p11_sign_settlement(struct keyd_p11 *p, const unsigned char *file, size_t file_len, unsigned char *sig,
                             size_t *sig_len)
{
    CK_OBJECT_HANDLE key;
    int rc = object(p, CKO_PRIVATE_KEY, KEYD_SETTLEMENT_LABEL, &key);
    if (rc != KEYD_OK)
        return rc;

    CK_RSA_PKCS_PSS_PARAMS pss_params = { CKM_SHA256, CKG_MGF1_SHA256, 32 };
    CK_MECHANISM pss = { CKM_SHA256_RSA_PKCS_PSS, &pss_params, sizeof pss_params };
    CK_RV rv = p->fn->C_SignInit(p->session, &pss, key);
    if (rv != CKR_OK) {
        log_err("token: settlement signing refused (rv=0x%lx)", (unsigned long)rv);
        return KEYD_ERR_TOKEN;
    }
    CK_ULONG len = (CK_ULONG)*sig_len;
    rv = p->fn->C_Sign(p->session, (CK_BYTE_PTR)file, file_len, sig, &len);
    if (rv != CKR_OK)
        return KEYD_ERR_TOKEN;
    *sig_len = len;
    return KEYD_OK;
}
