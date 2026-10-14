/*
 * Delivery receipts. Billing keeps signed receipts as proof of delivery for disputes that can come
 * up years later. The receipt key is rotated every quarter; billing keeps every public key.
 */
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#include "keyd/algorithms.h"
#include "keyd/crypto_api.h"
#include "keyd/keyd.h"
#include "util/log.h"

static EVP_PKEY *receipt_key;

int keyd_receipt_key_load(const char *path)
{
    FILE *fp = fopen(path, "r");
    if (fp == NULL)
        return KEYD_ERR_NOTFOUND;
    EVP_PKEY *key = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    if (key == NULL)
        return KEYD_ERR_ARGS;
    EVP_PKEY_free(receipt_key);
    receipt_key = key;
    return KEYD_OK;
}

int keyd_receipt_key_rotate(const char *path)
{
    EVP_PKEY *key = NULL;
    EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_from_name(NULL, KEYD_RECEIPT_SIG_ALG, NULL);
    if (kctx == NULL || EVP_PKEY_keygen_init(kctx) <= 0 || EVP_PKEY_generate(kctx, &key) <= 0) {
        log_openssl_errors("receipt: key rotation");
        EVP_PKEY_CTX_free(kctx);
        return KEYD_ERR_LIB;
    }
    EVP_PKEY_CTX_free(kctx);

    int rc = KEYD_OK;
    if (path != NULL) {
        mode_t old = umask(077);
        FILE *fp = fopen(path, "w");
        umask(old);
        if (fp == NULL || PEM_write_PrivateKey(fp, key, NULL, NULL, 0, NULL, NULL) != 1)
            rc = KEYD_ERR_IO;
        if (fp != NULL)
            fclose(fp);
    }
    if (rc == KEYD_OK) {
        EVP_PKEY_free(receipt_key);
        receipt_key = key;
    } else {
        EVP_PKEY_free(key);
    }
    return rc;
}

void keyd_receipt_key_free(void)
{
    EVP_PKEY_free(receipt_key);
    receipt_key = NULL;
}

static int receipt_message(const struct receipt *r, char *out, size_t cap)
{
    int n = snprintf(out, cap, "tbk-receipt-v1\n%s\n%s\n%s\n%lld\n", r->consignment, r->depot, r->signed_by,
                     (long long)r->delivered_at);
    return n > 0 && (size_t)n < cap ? n : -1;
}

int keyd_receipt_sign(const struct receipt *r, unsigned char *sig, size_t sig_cap, size_t *sig_len)
{
    char msg[256];
    if (receipt_key == NULL)
        return KEYD_ERR_ARGS;
    int n = receipt_message(r, msg, sizeof msg);
    if (n < 0)
        return KEYD_ERR_ARGS;

    EVP_MD_CTX *mctx = EVP_MD_CTX_new();
    int rc = KEYD_ERR_LIB;
    *sig_len = sig_cap;
    if (mctx != NULL && EVP_DigestSignInit_ex(mctx, NULL, NULL, NULL, NULL, receipt_key, NULL) == 1
        && EVP_DigestSign(mctx, sig, sig_len, (const unsigned char *)msg, (size_t)n) == 1)
        rc = KEYD_OK;
    EVP_MD_CTX_free(mctx);
    if (rc != KEYD_OK)
        log_openssl_errors("receipt: signing");
    return rc;
}
