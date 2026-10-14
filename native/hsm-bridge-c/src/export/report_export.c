/*
 * Auditor exports: the audit records between two dates as CSV, encrypted with a key derived from the
 * export password the auditors agree with the security team for each engagement. The auditors' tool
 * only opens CBC files and derives key and IV from the password with its own fixed salt.
 *
 * File: "TBX1" | iterations (4, big endian) | ciphertext.
 */
#include <dirent.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "keyd/export.h"
#include "keyd/keyd.h"
#include "keyd/paths.h"
#include "util/crypto_util.h"
#include "util/log.h"

#define EXPORT_MAGIC "TBX1"
#define EXPORT_MAX_PLAIN (32u << 20)

static const unsigned char EXPORT_SALT[16] = { 0x7c, 0x1e, 0xa4, 0x52, 0x09, 0xd3, 0x6b, 0x88, 0x2f, 0xc1, 0x5e, 0x90, 0x37, 0xb4, 0x6d, 0x0a };

static int export_key(const struct export_profile *profile, const char *pass, unsigned char *key_iv, size_t len)
{
    unsigned int iterations = profile->kdf_iterations;
    EVP_KDF *pbkdf2 = EVP_KDF_fetch(NULL, "PBKDF2", NULL);
    EVP_KDF_CTX *kctx = pbkdf2 ? EVP_KDF_CTX_new(pbkdf2) : NULL;
    OSSL_PARAM params[5], *p = params;
    int rc = KEYD_ERR_LIB;

    if (kctx == NULL)
        goto out;
    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, (char *)profile->kdf_digest, 0);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PASSWORD, (void *)pass, strlen(pass));
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, (void *)EXPORT_SALT, sizeof EXPORT_SALT);
    *p++ = OSSL_PARAM_construct_uint(OSSL_KDF_PARAM_ITER, &iterations);
    *p = OSSL_PARAM_construct_end();
    if (EVP_KDF_derive(kctx, key_iv, len, params) == 1)
        rc = KEYD_OK;
out:
    if (rc != KEYD_OK)
        log_openssl_errors("export: key derivation");
    EVP_KDF_CTX_free(kctx);
    EVP_KDF_free(pbkdf2);
    return rc;
}

static int csv_field(struct keyd_buf *out, const char *s, int last)
{
    int rc = keyd_buf_append(out, "\"", 1);
    for (; rc == KEYD_OK && *s; s++)
        rc = *s == '"' ? keyd_buf_append(out, "\"\"", 2) : keyd_buf_append(out, s, 1);
    if (rc == KEYD_OK)
        rc = keyd_buf_append(out, last ? "\"\n" : "\",", 2);
    return rc;
}

/* One audit line: seq, time, actor, action, detail, tag (tab separated). */
static int append_record(struct keyd_buf *csv, char *line, time_t from, time_t to)
{
    char *fields[6];
    char *save = NULL;
    int n = 0;
    for (char *f = strtok_r(line, "\t\n", &save); f != NULL && n < 6; f = strtok_r(NULL, "\t\n", &save))
        fields[n++] = f;
    if (n != 6)
        return KEYD_OK;
    time_t at = (time_t)strtoll(fields[1], NULL, 10);
    if (at < from || at >= to)
        return KEYD_OK;
    int rc = KEYD_OK;
    for (int i = 0; i < 6 && rc == KEYD_OK; i++)
        rc = csv_field(csv, fields[i], i == 5);
    return rc;
}

static int collect_csv(time_t from, time_t to, struct keyd_buf *csv)
{
    char path[512], line[1024];
    DIR *dir = opendir(KEYD_AUDIT_DIR);
    if (dir == NULL)
        return KEYD_ERR_IO;

    int rc = keyd_buf_printf(csv, "seq,time,actor,action,detail,tag\n");
    struct dirent *de;
    while (rc == KEYD_OK && (de = readdir(dir)) != NULL) {
        size_t n = strlen(de->d_name);
        if (n < 5 || strcmp(de->d_name + n - 4, ".log") != 0)
            continue;
        snprintf(path, sizeof path, "%s/%s", KEYD_AUDIT_DIR, de->d_name);
        FILE *fp = fopen(path, "r");
        if (fp == NULL)
            continue;
        while (rc == KEYD_OK && fgets(line, sizeof line, fp) != NULL)
            rc = append_record(csv, line, from, to);
        fclose(fp);
        if (csv->len > EXPORT_MAX_PLAIN)
            rc = KEYD_ERR_POLICY;
    }
    closedir(dir);
    return rc;
}

static int encrypt_csv(const struct export_profile *profile, const unsigned char *key, const unsigned char *iv,
                       const struct keyd_buf *csv, struct keyd_buf *out)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int n = 0, fin = 0, rc = KEYD_ERR_LIB;

    if (ctx == NULL || keyd_buf_reserve(out, csv->len + 32) != KEYD_OK)
        goto out;
    if (EVP_EncryptInit_ex2(ctx, profile->cipher(), key, iv, NULL) != 1)
        goto out;
    if (EVP_EncryptUpdate(ctx, out->data + out->len, &n, csv->data, (int)csv->len) != 1)
        goto out;
    if (EVP_EncryptFinal_ex(ctx, out->data + out->len + n, &fin) != 1)
        goto out;
    out->len += (size_t)n + (size_t)fin;
    rc = KEYD_OK;
out:
    EVP_CIPHER_CTX_free(ctx);
    return rc;
}

int keyd_export_report(const struct export_profile *profile, const char *pass, time_t from, time_t to,
                       struct keyd_buf *out)
{
    unsigned char key_iv[64];
    struct keyd_buf csv = { 0 };
    size_t kl = profile->key_len, il = profile->iv_len;

    if (strlen(pass) < 16 || to <= from || kl + il > sizeof key_iv)
        return KEYD_ERR_ARGS;
    int rc = collect_csv(from, to, &csv);
    if (rc == KEYD_OK)
        rc = export_key(profile, pass, key_iv, kl + il);
    if (rc == KEYD_OK) {
        unsigned char hdr[8] = { 'T', 'B', 'X', '1' };
        hdr[4] = (unsigned char)(profile->kdf_iterations >> 24);
        hdr[5] = (unsigned char)(profile->kdf_iterations >> 16);
        hdr[6] = (unsigned char)(profile->kdf_iterations >> 8);
        hdr[7] = (unsigned char)profile->kdf_iterations;
        rc = keyd_buf_append(out, hdr, sizeof hdr);
    }
    if (rc == KEYD_OK)
        rc = encrypt_csv(profile, key_iv, key_iv + kl, &csv, out);
    if (rc == KEYD_OK)
        log_info("export: %zu bytes of audit records for profile %s", csv.len, profile->name);
    crypto_wipe(key_iv, sizeof key_iv);
    keyd_buf_free(&csv);
    return rc;
}
