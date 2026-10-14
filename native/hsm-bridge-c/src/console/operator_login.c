/*
 * Operator console accounts. The operators file has one "name:hash:failures" line per operator; the
 * hash string carries its own scheme and setting, so verification follows whatever it was created
 * with. New passwords get a fresh setting from libxcrypt.
 */
#include <crypt.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "keyd/audit.h"
#include "keyd/crypto_api.h"
#include "keyd/keyd.h"
#include "util/crypto_util.h"
#include "util/hash_table.h"
#include "util/log.h"

#define MAX_OPERATORS 64
#define MAX_FAILURES 5
#define LINE_MAX_LEN 512

struct operator_entry {
    char name[48];
    char hash[256];
    unsigned int failures;
};

struct operator_db {
    struct operator_entry ops[MAX_OPERATORS];
    size_t count;
};

static const char *operators_path;

static int valid_name(const char *user)
{
    size_t n = strlen(user);
    if (n == 0 || n >= sizeof((struct operator_entry *)0)->name)
        return 0;
    for (size_t i = 0; i < n; i++) {
        char c = user[i];
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '-'))
            return 0;
    }
    return 1;
}

static int load_db(struct operator_db *db)
{
    memset(db, 0, sizeof *db);
    FILE *fp = fopen(operators_path, "r");
    if (fp == NULL)
        return errno == ENOENT ? KEYD_OK : KEYD_ERR_IO;

    char line[LINE_MAX_LEN];
    while (fgets(line, sizeof line, fp) != NULL && db->count < MAX_OPERATORS) {
        line[strcspn(line, "\n")] = '\0';
        char *name = strtok(line, ":");
        char *hash = strtok(NULL, ":");
        char *fails = strtok(NULL, ":");
        if (name == NULL || hash == NULL)
            continue;
        struct operator_entry *e = &db->ops[db->count++];
        snprintf(e->name, sizeof e->name, "%s", name);
        snprintf(e->hash, sizeof e->hash, "%s", hash);
        e->failures = fails ? (unsigned int)strtoul(fails, NULL, 10) : 0;
    }
    fclose(fp);
    return KEYD_OK;
}

static int save_db(const struct operator_db *db)
{
    struct keyd_buf out = { 0 };
    int rc = KEYD_OK;
    for (size_t i = 0; i < db->count && rc == KEYD_OK; i++)
        rc = keyd_buf_printf(&out, "%s:%s:%u\n", db->ops[i].name, db->ops[i].hash, db->ops[i].failures);
    if (rc == KEYD_OK)
        rc = keyd_write_file(operators_path, out.data, out.len, 0600);
    keyd_buf_free(&out);
    return rc;
}

static struct operator_entry *find_operator(struct operator_db *db, const char *user)
{
    for (size_t i = 0; i < db->count; i++) {
        if (strcmp(db->ops[i].name, user) == 0)
            return &db->ops[i];
    }
    return NULL;
}

static int sign_in_operator(const char *user, const char *password)
{
    struct operator_db db;
    int rc = load_db(&db);
    if (rc != KEYD_OK)
        return rc;

    struct operator_entry *e = find_operator(&db, user);
    if (e == NULL)
        return KEYD_ERR_AUTH;
    if (e->failures >= MAX_FAILURES) {
        log_warn("console: %s is locked after %u failed attempts", user, e->failures);
        return KEYD_ERR_POLICY;
    }

    struct crypt_data *cd = calloc(1, sizeof *cd);
    if (cd == NULL)
        return KEYD_ERR_NOMEM;
    const char *computed = crypt_r(password, e->hash, cd);
    size_t n = strlen(e->hash);
    int ok = computed != NULL && computed[0] != '*' && strlen(computed) == n && crypto_memeq(computed, e->hash, n);
    crypto_wipe(cd, sizeof *cd);
    free(cd);

    e->failures = ok ? 0 : e->failures + 1;
    save_db(&db);
    return ok ? KEYD_OK : KEYD_ERR_AUTH;
}

int keyd_operator_login(const char *path, const char *user, const char *password)
{
    if (!valid_name(user))
        return KEYD_ERR_ARGS;
    operators_path = path;
    int rc = sign_in_operator(user, password);
    const char *who = keyd_intern(user);
    keyd_audit_append(who ? who : "?", "console-login", "%s", rc == KEYD_OK ? "accepted" : keyd_status_str(rc));
    return rc;
}

int keyd_operator_set_password(const char *path, const char *user, const char *password)
{
    if (!valid_name(user) || strlen(password) < 12)
        return KEYD_ERR_ARGS;
    operators_path = path;

    struct operator_db db;
    int rc = load_db(&db);
    if (rc != KEYD_OK)
        return rc;

    char setting[CRYPT_GENSALT_OUTPUT_SIZE];
    if (crypt_gensalt_rn("$y$", 0, NULL, 0, setting, sizeof setting) == NULL) {
        log_err("console: no password setting available: %s", strerror(errno));
        return KEYD_ERR_LIB;
    }

    struct crypt_data *cd = calloc(1, sizeof *cd);
    if (cd == NULL)
        return KEYD_ERR_NOMEM;
    const char *hash = crypt_r(password, setting, cd);
    if (hash == NULL || hash[0] == '*') {
        free(cd);
        return KEYD_ERR_LIB;
    }

    struct operator_entry *e = find_operator(&db, user);
    if (e == NULL) {
        if (db.count == MAX_OPERATORS) {
            free(cd);
            return KEYD_ERR_POLICY;
        }
        e = &db.ops[db.count++];
        snprintf(e->name, sizeof e->name, "%s", user);
    }
    snprintf(e->hash, sizeof e->hash, "%s", hash);
    e->failures = 0;
    crypto_wipe(cd, sizeof *cd);
    free(cd);

    rc = save_db(&db);
    if (rc == KEYD_OK)
        keyd_audit_append(user, "console-password", "set");
    return rc;
}
