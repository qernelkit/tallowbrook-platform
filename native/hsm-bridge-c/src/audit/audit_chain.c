/*
 * Audit records are chained: each record's tag covers the previous tag and the digest of the record
 * body, keyed with the chain key, so a removed or edited record breaks every tag after it. Records
 * are appended to the day's file and grouped into segments that segment_seal.c seals for the
 * archive.
 */
#include "keyd/audit.h"

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "keyd/keyd.h"
#include "util/crypto_util.h"
#include "util/log.h"

#ifndef KEYD_AUDIT_DIGEST
#error "KEYD_AUDIT_DIGEST is set by the build"
#endif

static EVP_MAC *chain_mac;
static EVP_MD *record_md;
static unsigned char chain_key[64];
static size_t chain_key_len;
static unsigned char prev_tag[KEYD_AUDIT_TAG_LEN];
static uint64_t next_seq = 1;
static FILE *day_file;
static char audit_dir[256];
static int day_of_file = -1;

int keyd_audit_open(const char *dir, const unsigned char *key, size_t key_len)
{
    if (key_len == 0 || key_len > sizeof chain_key)
        return KEYD_ERR_ARGS;
    EVP_MAC *mac = EVP_MAC_fetch(NULL, "KMAC-256", NULL);
    EVP_MD *md = EVP_MD_fetch(NULL, KEYD_AUDIT_DIGEST, NULL);
    if (mac == NULL || md == NULL) {
        log_openssl_errors("audit: algorithm fetch");
        EVP_MAC_free(mac);
        EVP_MD_free(md);
        return KEYD_ERR_LIB;
    }
    chain_mac = mac;
    record_md = md;
    memcpy(chain_key, key, key_len);
    chain_key_len = key_len;
    snprintf(audit_dir, sizeof audit_dir, "%s", dir);
    memset(prev_tag, 0, sizeof prev_tag);
    return KEYD_OK;
}

static int open_day_file(const struct tm *tm)
{
    char path[384];
    if (day_file != NULL && tm->tm_yday == day_of_file)
        return KEYD_OK;
    if (day_file != NULL)
        fclose(day_file);
    snprintf(path, sizeof path, "%s/%04d-%02d-%02d.log", audit_dir, tm->tm_year + 1900, tm->tm_mon + 1,
             tm->tm_mday);
    day_file = fopen(path, "a");
    if (day_file == NULL) {
        log_err("audit: cannot open %s", path);
        return KEYD_ERR_IO;
    }
    day_of_file = tm->tm_yday;
    return KEYD_OK;
}

static int record_tag(const unsigned char *body, size_t body_len, unsigned char tag[KEYD_AUDIT_TAG_LEN])
{
    unsigned char body_sum[EVP_MAX_MD_SIZE];
    unsigned int sum_len = 0;
    int rc = KEYD_ERR_LIB;

    if (EVP_Digest(body, body_len, body_sum, &sum_len, record_md, NULL) != 1)
        return KEYD_ERR_LIB;

    EVP_MAC_CTX *ctx = EVP_MAC_CTX_new(chain_mac);
    OSSL_PARAM params[2];
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_CUSTOM, (char *)"tbkeyd-audit", 0);
    params[1] = OSSL_PARAM_construct_end();
    size_t out_len = 0;
    if (ctx != NULL && EVP_MAC_init(ctx, chain_key, chain_key_len, params) == 1
        && EVP_MAC_update(ctx, prev_tag, sizeof prev_tag) == 1 && EVP_MAC_update(ctx, body_sum, sum_len) == 1
        && EVP_MAC_final(ctx, tag, &out_len, KEYD_AUDIT_TAG_LEN) == 1 && out_len == KEYD_AUDIT_TAG_LEN)
        rc = KEYD_OK;
    EVP_MAC_CTX_free(ctx);
    return rc;
}

int keyd_audit_append_record(struct audit_record *rec, unsigned char tag[KEYD_AUDIT_TAG_LEN])
{
    char body[512], tag_hex[2 * KEYD_AUDIT_TAG_LEN + 1];
    struct tm tm;

    if (chain_mac == NULL)
        return KEYD_ERR_ARGS;
    rec->seq = next_seq;
    if (rec->at == 0)
        rec->at = time(NULL);
    int n = snprintf(body, sizeof body, "%llu\t%lld\t%s\t%s\t%s", (unsigned long long)rec->seq, (long long)rec->at,
                     rec->actor, rec->action, rec->detail);
    if (n < 0 || (size_t)n >= sizeof body)
        return KEYD_ERR_ARGS;

    int rc = record_tag((const unsigned char *)body, (size_t)n, tag);
    if (rc != KEYD_OK)
        return rc;
    gmtime_r(&rec->at, &tm);
    if ((rc = open_day_file(&tm)) != KEYD_OK)
        return rc;
    crypto_hex_encode(tag_hex, sizeof tag_hex, tag, KEYD_AUDIT_TAG_LEN);
    if (fprintf(day_file, "%s\t%s\n", body, tag_hex) < 0)
        return KEYD_ERR_IO;
    memcpy(prev_tag, tag, KEYD_AUDIT_TAG_LEN);
    next_seq++;
    return KEYD_OK;
}

int keyd_audit_append(const char *actor, const char *action, const char *fmt, ...)
{
    struct audit_record rec;
    unsigned char tag[KEYD_AUDIT_TAG_LEN];
    va_list ap;

    memset(&rec, 0, sizeof rec);
    snprintf(rec.actor, sizeof rec.actor, "%s", actor);
    snprintf(rec.action, sizeof rec.action, "%s", action);
    va_start(ap, fmt);
    vsnprintf(rec.detail, sizeof rec.detail, fmt, ap);
    va_end(ap);
    for (char *p = rec.detail; *p; p++) {
        if (*p == '\t' || *p == '\n')
            *p = ' ';
    }
    int rc = keyd_audit_append_record(&rec, tag);
    if (rc != KEYD_OK && chain_mac != NULL)
        log_err("audit: record for %s/%s not written: %s", actor, action, keyd_status_str(rc));
    return chain_mac == NULL ? KEYD_OK : rc;
}

int keyd_audit_flush(void)
{
    if (day_file != NULL && fflush(day_file) != 0)
        return KEYD_ERR_IO;
    return KEYD_OK;
}

uint64_t keyd_audit_last_seq(void)
{
    return next_seq - 1;
}

void keyd_audit_close(void)
{
    if (day_file != NULL)
        fclose(day_file);
    day_file = NULL;
    day_of_file = -1;
    EVP_MAC_free(chain_mac);
    EVP_MD_free(record_md);
    chain_mac = NULL;
    record_md = NULL;
    crypto_wipe(chain_key, sizeof chain_key);
}
