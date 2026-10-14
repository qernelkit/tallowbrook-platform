/*
 * Archive key escrow. Every archive key that vaultarc registers is escrowed to two independent
 * recipients run by different teams, so losing one escrow agent never loses footage. For each
 * recipient tbkeyd encapsulates against the recipient's public key, runs the shared secret through
 * the link key schedule (salted with the archive id, labelled with the recipient) and seals the
 * archive key with the result.
 *
 * Output, one line per recipient: "<label> <kem> <ciphertext hex> <sealed key hex>".
 */
#include <oqs/oqs.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "keyd/crypto_api.h"
#include "keyd/keyd.h"
#include "keyd/link.h"
#include "keyd/paths.h"
#include "util/crypto_util.h"
#include "util/log.h"

struct escrow_recipient {
    const char *label;
    const char *kem_alg;
};

static const struct escrow_recipient ESCROW_RECIPIENTS[] = {
    { .label = "escrow-primary", .kem_alg = OQS_KEM_alg_ml_kem_1024 },
    { .label = "escrow-secondary", .kem_alg = OQS_KEM_alg_frodokem_976_aes },
};

#define RECIPIENT_COUNT (sizeof ESCROW_RECIPIENTS / sizeof ESCROW_RECIPIENTS[0])
#define ARCHIVE_KEY_LEN 32

static int primary_public(struct keyd_buf *pub)
{
    FILE *fp = fopen(KEYD_ESCROW_PUB_FILE, "r");
    if (fp == NULL) {
        log_err("escrow: cannot open the primary recipient key");
        return KEYD_ERR_IO;
    }
    EVP_PKEY *pkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    fclose(fp);
    if (pkey == NULL)
        return KEYD_ERR_ARGS;

    size_t len = 0;
    int rc = KEYD_ERR_ARGS;
    if (EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY, NULL, 0, &len) == 1
        && keyd_buf_reserve(pub, len) == KEYD_OK
        && EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY, pub->data, len, &len) == 1) {
        pub->len = len;
        rc = KEYD_OK;
    }
    EVP_PKEY_free(pkey);
    return rc;
}

static int recipient_public(const struct escrow_recipient *r, struct keyd_buf *pub)
{
    if (strcmp(r->label, "escrow-primary") == 0)
        return primary_public(pub);
    return keyd_read_file(KEYD_ESCROW_SECONDARY_FILE, 64 * 1024, pub);
}

static int append_hex(struct keyd_buf *out, const unsigned char *p, size_t n)
{
    int rc = keyd_buf_reserve(out, 2 * n + 1);
    if (rc != KEYD_OK)
        return rc;
    crypto_hex_encode((char *)out->data + out->len, out->cap - out->len, p, n);
    out->len += 2 * n;
    return KEYD_OK;
}

static OQS_KEM *recipient_kem(const struct escrow_recipient *r)
{
    OQS_KEM *kem = OQS_KEM_new(r->kem_alg);
    if (kem == NULL)
        log_err("escrow: %s: method not available in this liboqs build", r->label);
    return kem;
}

static int wrap_for(const struct escrow_recipient *r, const unsigned char archive_key[ARCHIVE_KEY_LEN],
                    const char *archive_id, struct keyd_buf *out)
{
    struct keyd_buf pub = { 0 };
    unsigned char ss[64], kw[KEYD_LINK_KEY_LEN + KEYD_LINK_IV_LEN];
    unsigned char sealed[ARCHIVE_KEY_LEN + KEYD_LINK_TAG_LEN];
    unsigned char *ct = NULL;
    int rc = KEYD_ERR_LIB;

    OQS_KEM *kem = recipient_kem(r);
    if (kem == NULL)
        return KEYD_ERR_LIB;
    if ((rc = recipient_public(r, &pub)) != KEYD_OK)
        goto out;
    if (pub.len != kem->length_public_key || kem->length_shared_secret > sizeof ss) {
        log_err("escrow: %s: recipient key has the wrong size (%zu bytes)", r->label, pub.len);
        rc = KEYD_ERR_ARGS;
        goto out;
    }
    ct = malloc(kem->length_ciphertext);
    if (ct == NULL) {
        rc = KEYD_ERR_NOMEM;
        goto out;
    }
    if (OQS_KEM_encaps(kem, ct, ss, pub.data) != OQS_SUCCESS) {
        rc = KEYD_ERR_LIB;
        goto out;
    }
    rc = keyd_kdf_expand(ss, kem->length_shared_secret, (const unsigned char *)archive_id, strlen(archive_id),
                         r->label, kw, sizeof kw);
    if (rc == KEYD_OK)
        rc = keyd_aead_seal(kw, kw + KEYD_LINK_KEY_LEN, (const unsigned char *)archive_id, strlen(archive_id),
                            archive_key, ARCHIVE_KEY_LEN, sealed);
    if (rc == KEYD_OK)
        rc = keyd_buf_printf(out, "%s %s ", r->label, kem->method_name);
    if (rc == KEYD_OK)
        rc = append_hex(out, ct, kem->length_ciphertext);
    if (rc == KEYD_OK)
        rc = keyd_buf_append(out, " ", 1);
    if (rc == KEYD_OK)
        rc = append_hex(out, sealed, sizeof sealed);
    if (rc == KEYD_OK)
        rc = keyd_buf_append(out, "\n", 1);
out:
    crypto_wipe(ss, sizeof ss);
    crypto_wipe(kw, sizeof kw);
    free(ct);
    keyd_buf_free(&pub);
    OQS_KEM_free(kem);
    return rc;
}

int keyd_escrow_archive_key(const unsigned char archive_key[ARCHIVE_KEY_LEN], const char *archive_id,
                            struct keyd_buf *out)
{
    if (strlen(archive_id) == 0 || strlen(archive_id) > 64)
        return KEYD_ERR_ARGS;
    for (size_t i = 0; i < RECIPIENT_COUNT; i++) {
        int rc = wrap_for(&ESCROW_RECIPIENTS[i], archive_key, archive_id, out);
        if (rc != KEYD_OK) {
            log_err("escrow: archive %s not escrowed to %s: %s", archive_id, ESCROW_RECIPIENTS[i].label,
                    keyd_status_str(rc));
            return rc;
        }
    }
    log_info("escrow: archive %s escrowed to %zu recipients", archive_id, RECIPIENT_COUNT);
    return KEYD_OK;
}
