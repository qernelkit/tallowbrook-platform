/*
 * Import of configuration backups from the key appliances tbkeyd replaced. The appliances wrote
 * their backups with `openssl enc`: the 8-byte "Salted__" magic, an 8-byte salt, then the body, with
 * key and IV derived from the backup password in one MD5 round. The body is "key = value" lines;
 * the settings we still use are copied into keyd.conf by the operator after review.
 */
#include <openssl/evp.h>
#include <string.h>

#include "keyd/crypto_api.h"
#include "keyd/keyd.h"
#include "util/crypto_util.h"
#include "util/log.h"

#define ENC_MAGIC "Salted__"
#define BACKUP_MAX (1u << 20)

static const char *const KEPT_SETTINGS[] = {
    "partition_label", "depot_list", "region", "syslog_host", "ntp_server",
};

static int kept(const char *name, size_t len)
{
    for (size_t i = 0; i < sizeof KEPT_SETTINGS / sizeof KEPT_SETTINGS[0]; i++) {
        if (strlen(KEPT_SETTINGS[i]) == len && strncmp(KEPT_SETTINGS[i], name, len) == 0)
            return 1;
    }
    return 0;
}

static int filter_settings(const unsigned char *body, size_t len, struct keyd_buf *settings)
{
    const char *p = (const char *)body, *end = p + len;
    int rc = KEYD_OK;
    while (p < end && rc == KEYD_OK) {
        const char *nl = memchr(p, '\n', (size_t)(end - p));
        const char *eol = nl ? nl : end;
        const char *eq = memchr(p, '=', (size_t)(eol - p));
        if (eq != NULL) {
            const char *name_end = eq;
            while (name_end > p && name_end[-1] == ' ')
                name_end--;
            if (kept(p, (size_t)(name_end - p)))
                rc = keyd_buf_printf(settings, "%.*s\n", (int)(eol - p), p);
        }
        p = nl ? nl + 1 : end;
    }
    return rc;
}

int keyd_appliance_import(const unsigned char *file, size_t file_len, const char *pass, struct keyd_buf *settings)
{
    unsigned char key[32], iv[16];
    unsigned char *body = NULL;
    int n = 0, fin = 0, rc = KEYD_ERR_ARGS;

    if (file_len < 32 || file_len > BACKUP_MAX || memcmp(file, ENC_MAGIC, 8) != 0)
        return KEYD_ERR_ARGS;
    const unsigned char *salt = file + 8;
    const unsigned char *in = file + 16;
    size_t in_len = file_len - 16;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    const EVP_CIPHER *cfg_cipher = EVP_aes_256_cbc();
    if (EVP_BytesToKey(cfg_cipher, EVP_md5(), salt, (const unsigned char *)pass, (int)strlen(pass), 1, key, iv) == 0)
        goto out;
    body = malloc(in_len + 16);
    if (ctx == NULL || body == NULL) {
        rc = KEYD_ERR_NOMEM;
        goto out;
    }
    rc = KEYD_ERR_LIB;
    if (EVP_DecryptInit_ex(ctx, cfg_cipher, NULL, key, iv) != 1)
        goto out;
    if (EVP_DecryptUpdate(ctx, body, &n, in, (int)in_len) != 1)
        goto out;
    if (EVP_DecryptFinal_ex(ctx, body + n, &fin) != 1) {
        log_warn("import: backup password rejected or file damaged");
        rc = KEYD_ERR_AUTH;
        goto out;
    }
    rc = filter_settings(body, (size_t)(n + fin), settings);
out:
    crypto_wipe(key, sizeof key);
    crypto_wipe(iv, sizeof iv);
    if (body != NULL)
        crypto_wipe(body, in_len + 16);
    free(body);
    EVP_CIPHER_CTX_free(ctx);
    return rc;
}
