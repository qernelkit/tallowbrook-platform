/*
 * Opening an archive for a claims investigation. vaultarc writes the archive key encapsulated to the
 * archive KEK; tbkeyd holds the KEK and hands the archive key back to an approved caller. Every
 * unwrap is audited by the request layer.
 */
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <stdio.h>
#include <string.h>

#include "keyd/crypto_api.h"
#include "keyd/keyd.h"
#include "keyd/paths.h"
#include "util/crypto_util.h"
#include "util/log.h"

static EVP_PKEY *archive_kek;

static int load_kek(void)
{
    if (archive_kek != NULL)
        return KEYD_OK;
    FILE *fp = fopen(KEYD_ARCHIVE_KEK_FILE, "r");
    if (fp == NULL) {
        log_err("archive: KEK file missing");
        return KEYD_ERR_IO;
    }
    archive_kek = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    if (archive_kek == NULL) {
        log_openssl_errors("archive: KEK file");
        return KEYD_ERR_ARGS;
    }
    return KEYD_OK;
}

int keyd_archive_unwrap(const unsigned char *encapsulated, size_t encapsulated_len, unsigned char archive_key[32])
{
    unsigned char secret[32];
    size_t secret_len = sizeof secret;
    int rc = load_kek();
    if (rc != KEYD_OK)
        return rc;

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_pkey(NULL, archive_kek, NULL);
    rc = KEYD_ERR_LIB;
    if (ctx == NULL || EVP_PKEY_decapsulate_init(ctx, NULL) <= 0)
        goto out;
    if (EVP_PKEY_decapsulate(ctx, secret, &secret_len, encapsulated, encapsulated_len) <= 0 || secret_len != 32)
        goto out;
    memcpy(archive_key, secret, 32);
    rc = KEYD_OK;
out:
    crypto_wipe(secret, sizeof secret);
    EVP_PKEY_CTX_free(ctx);
    return rc;
}
