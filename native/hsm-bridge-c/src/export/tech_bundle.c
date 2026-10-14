/*
 * Technician bundles. A field technician's laptop gets a key and certificate for the depot
 * maintenance VPN. tbkeyd creates the key and returns the public key; the PKI team's CA issues the
 * certificate; tbkeyd then packages key and certificate for the technician, protected with the
 * password the technician chose. The private key never leaves tbkeyd unprotected, and a pending key
 * is dropped if the certificate does not arrive in time.
 */
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/x509.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "keyd/export.h"
#include "keyd/keyd.h"
#include "util/hash_table.h"
#include "util/log.h"

struct pending_key {
    EVP_PKEY *key;
    time_t created;
};

static struct keyd_table pending;

static int valid_tech_id(const char *id)
{
    size_t n = strlen(id);
    if (n < 5 || n > 24 || strncmp(id, "TECH-", 5) != 0)
        return 0;
    for (size_t i = 5; i < n; i++) {
        if (id[i] < '0' || id[i] > '9')
            return 0;
    }
    return 1;
}

static void pending_free(void *v)
{
    struct pending_key *pk = v;
    EVP_PKEY_free(pk->key);
    free(pk);
}

static EVP_PKEY *tech_key_new(void)
{
    EVP_PKEY *key = NULL;
    EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    if (kctx == NULL || EVP_PKEY_keygen_init(kctx) <= 0)
        goto out;
    if (EVP_PKEY_CTX_set_group_name(kctx, "P-384") <= 0)
        goto out;
    if (EVP_PKEY_generate(kctx, &key) <= 0)
        key = NULL;
out:
    EVP_PKEY_CTX_free(kctx);
    return key;
}

int keyd_tech_key_begin(const char *tech_id, struct keyd_buf *public_pem)
{
    if (!valid_tech_id(tech_id))
        return KEYD_ERR_ARGS;
    if (pending.slots == NULL && keyd_table_init(&pending, 16) != KEYD_OK)
        return KEYD_ERR_NOMEM;

    struct pending_key *pk = calloc(1, sizeof *pk);
    if (pk == NULL)
        return KEYD_ERR_NOMEM;
    pk->key = tech_key_new();
    pk->created = time(NULL);
    if (pk->key == NULL) {
        free(pk);
        log_openssl_errors("tech: key generation");
        return KEYD_ERR_LIB;
    }

    BIO *bio = BIO_new(BIO_s_mem());
    char *pem = NULL;
    long pem_len = 0;
    int rc = KEYD_ERR_LIB;
    if (bio != NULL && PEM_write_bio_PUBKEY(bio, pk->key) == 1 && (pem_len = BIO_get_mem_data(bio, &pem)) > 0)
        rc = keyd_buf_append(public_pem, pem, (size_t)pem_len);
    BIO_free(bio);
    if (rc != KEYD_OK) {
        pending_free(pk);
        return rc;
    }
    void *old = keyd_table_remove(&pending, tech_id);
    if (old != NULL)
        pending_free(old);
    return keyd_table_put(&pending, tech_id, pk);
}

int keyd_tech_bundle_finish(const char *tech_id, const char *cert_pem, const char *pass, struct keyd_buf *out)
{
    if (!valid_tech_id(tech_id) || strlen(pass) < 10)
        return KEYD_ERR_ARGS;
    struct pending_key *pk = keyd_table_get(&pending, tech_id);
    if (pk == NULL)
        return KEYD_ERR_NOTFOUND;

    BIO *in = BIO_new_mem_buf(cert_pem, -1);
    X509 *cert = in ? PEM_read_bio_X509(in, NULL, NULL, NULL) : NULL;
    BIO_free(in);
    if (cert == NULL || X509_check_private_key(cert, pk->key) != 1) {
        X509_free(cert);
        log_warn("tech: certificate for %s does not match the pending key", tech_id);
        return KEYD_ERR_ARGS;
    }

    char label[48];
    snprintf(label, sizeof label, "Tallowbrook depot maintenance (%s)", tech_id);
    int rc = KEYD_ERR_LIB;
    PKCS12 *p12 = PKCS12_create(pass, label, pk->key, cert, NULL, 0, 0, 0, 0, 0);
    BIO *mem = BIO_new(BIO_s_mem());
    char *der = NULL;
    long der_len = 0;
    if (p12 != NULL && mem != NULL && i2d_PKCS12_bio(mem, p12) == 1 && (der_len = BIO_get_mem_data(mem, &der)) > 0)
        rc = keyd_buf_append(out, der, (size_t)der_len);
    BIO_free(mem);
    PKCS12_free(p12);
    X509_free(cert);
    if (rc == KEYD_OK) {
        pending_free(keyd_table_remove(&pending, tech_id));
        log_info("tech: bundle issued for %s", tech_id);
    }
    return rc;
}

static int expire_one(const char *key, void *value, void *arg)
{
    const struct pending_key *pk = value;
    time_t now = *(const time_t *)arg;
    if (now - pk->created > KEYD_TECH_PENDING_S) {
        log_info("tech: pending key for %s expired", key);
        pending_free(keyd_table_remove(&pending, key));
    }
    return 0;
}

void keyd_tech_expire(time_t now)
{
    if (pending.slots != NULL)
        keyd_table_each(&pending, expire_one, &now);
}
