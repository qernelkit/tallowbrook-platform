/*
 * Keys for partner portals (customs brokers, two retailers) whose API gateways only take RSA client
 * keys. The integration agent on this host uses the private key; the public key is uploaded to the
 * partner's portal by the integrations team.
 */
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#include "keyd/crypto_api.h"
#include "keyd/keyd.h"
#include "util/log.h"

static int valid_partner(const char *partner)
{
    size_t n = strlen(partner);
    if (n == 0 || n > 32)
        return 0;
    for (size_t i = 0; i < n; i++) {
        char c = partner[i];
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-'))
            return 0;
    }
    return 1;
}

static int store_private(const char *dir, const char *partner, EVP_PKEY *key)
{
    char path[512];
    snprintf(path, sizeof path, "%s/%s.pem", dir, partner);
    mode_t old = umask(077);
    FILE *fp = fopen(path, "w");
    umask(old);
    if (fp == NULL)
        return KEYD_ERR_IO;
    int ok = PEM_write_PrivateKey(fp, key, NULL, NULL, 0, NULL, NULL) == 1;
    ok = fclose(fp) == 0 && ok;
    return ok ? KEYD_OK : KEYD_ERR_IO;
}

int keyd_partner_key_create(const char *dir, const char *partner, struct keyd_buf *public_pem)
{
    EVP_PKEY *key = NULL;
    int rc = KEYD_ERR_LIB;

    if (!valid_partner(partner))
        return KEYD_ERR_ARGS;
    EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
    if (kctx == NULL || EVP_PKEY_keygen_init(kctx) <= 0)
        goto out;
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(kctx, 3072) <= 0)
        goto out;
    if (EVP_PKEY_generate(kctx, &key) <= 0)
        goto out;

    if ((rc = store_private(dir, partner, key)) != KEYD_OK)
        goto out;
    BIO *bio = BIO_new(BIO_s_mem());
    char *pem = NULL;
    long pem_len = 0;
    rc = KEYD_ERR_LIB;
    if (bio != NULL && PEM_write_bio_PUBKEY(bio, key) == 1 && (pem_len = BIO_get_mem_data(bio, &pem)) > 0)
        rc = keyd_buf_append(public_pem, pem, (size_t)pem_len);
    BIO_free(bio);
    if (rc == KEYD_OK)
        log_info("partner: new client key for %s", partner);
out:
    if (rc == KEYD_ERR_LIB)
        log_openssl_errors("partner: key creation");
    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(kctx);
    return rc;
}
