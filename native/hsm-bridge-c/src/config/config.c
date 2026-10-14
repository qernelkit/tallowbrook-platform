#include "config/config.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "keyd/keyd.h"
#include "keyd/paths.h"
#include "keyd/tls_profile.h"

void keyd_config_defaults(struct keyd_config *cfg)
{
    memset(cfg, 0, sizeof *cfg);
    snprintf(cfg->listen_addr, sizeof cfg->listen_addr, "0.0.0.0");
    cfg->listen_port = KEYD_LISTEN_PORT;
    snprintf(cfg->card_module, sizeof cfg->card_module, "%s", KEYD_TOKEN_MODULE);
    snprintf(cfg->log_level, sizeof cfg->log_level, "info");
    snprintf(cfg->agent_host, sizeof cfg->agent_host, "127.0.0.1");
    cfg->agent_port = 8085;
    snprintf(cfg->release_dir, sizeof cfg->release_dir, "%s", KEYD_RELEASE_DIR);
    cfg->max_request_kb = 256;
}

static char *trim(char *s)
{
    while (isspace((unsigned char)*s))
        s++;
    char *end = s + strlen(s);
    while (end > s && isspace((unsigned char)end[-1]))
        *--end = '\0';
    return s;
}

static int set_port(unsigned short *out, const char *value)
{
    char *end = NULL;
    long v = strtol(value, &end, 10);
    if (*end != '\0' || v < 1 || v > 65535)
        return -1;
    *out = (unsigned short)v;
    return 0;
}

static int set_string(char *dst, size_t cap, const char *value)
{
    return snprintf(dst, cap, "%s", value) < (int)cap ? 0 : -1;
}

static int apply(struct keyd_config *cfg, const char *name, const char *value)
{
    if (strcmp(name, "listen_addr") == 0)
        return set_string(cfg->listen_addr, sizeof cfg->listen_addr, value);
    if (strcmp(name, "listen_port") == 0)
        return set_port(&cfg->listen_port, value);
    if (strcmp(name, "p11_module") == 0)
        return set_string(cfg->p11_module, sizeof cfg->p11_module, value);
    if (strcmp(name, "p11_slot_label") == 0)
        return set_string(cfg->p11_slot_label, sizeof cfg->p11_slot_label, value);
    if (strcmp(name, "card_module") == 0)
        return set_string(cfg->card_module, sizeof cfg->card_module, value);
    if (strcmp(name, "log_level") == 0)
        return set_string(cfg->log_level, sizeof cfg->log_level, value);
    if (strcmp(name, "syslog") == 0) {
        cfg->use_syslog = strcmp(value, "yes") == 0 || strcmp(value, "true") == 0;
        return 0;
    }
    if (strcmp(name, "archive_agent") == 0) {
        char host[64];
        const char *colon = strrchr(value, ':');
        if (colon == NULL || (size_t)(colon - value) >= sizeof host)
            return -1;
        memcpy(host, value, (size_t)(colon - value));
        host[colon - value] = '\0';
        if (set_port(&cfg->agent_port, colon + 1) != 0)
            return -1;
        return set_string(cfg->agent_host, sizeof cfg->agent_host, host);
    }
    if (strcmp(name, "release_dir") == 0)
        return set_string(cfg->release_dir, sizeof cfg->release_dir, value);
    if (strcmp(name, "max_request_kb") == 0) {
        long v = strtol(value, NULL, 10);
        if (v < 4 || v > 65536)
            return -1;
        cfg->max_request_kb = (unsigned int)v;
        return 0;
    }
    return -2;
}

int keyd_config_parse(struct keyd_config *cfg, const char *text, size_t len, char *err, size_t err_cap)
{
    char line[512];
    size_t pos = 0;
    int lineno = 0;

    while (pos < len) {
        size_t n = 0;
        while (pos < len && text[pos] != '\n') {
            if (n + 1 < sizeof line)
                line[n++] = text[pos];
            pos++;
        }
        pos++;
        line[n] = '\0';
        lineno++;

        char *s = trim(line);
        if (*s == '\0' || *s == '#')
            continue;
        char *eq = strchr(s, '=');
        if (eq == NULL) {
            snprintf(err, err_cap, "line %d: expected name = value", lineno);
            return KEYD_ERR_ARGS;
        }
        *eq = '\0';
        char *name = trim(s);
        char *value = trim(eq + 1);
        int rc = apply(cfg, name, value);
        if (rc == -2) {
            snprintf(err, err_cap, "line %d: unknown setting '%s'", lineno, name);
            return KEYD_ERR_ARGS;
        }
        if (rc != 0) {
            snprintf(err, err_cap, "line %d: bad value for '%s'", lineno, name);
            return KEYD_ERR_ARGS;
        }
    }
    if (cfg->p11_module[0] == '\0' || cfg->p11_slot_label[0] == '\0') {
        snprintf(err, err_cap, "p11_module and p11_slot_label are required");
        return KEYD_ERR_ARGS;
    }
    return KEYD_OK;
}

int keyd_config_load(struct keyd_config *cfg, const char *path, char *err, size_t err_cap)
{
    struct keyd_buf text = { 0 };
    keyd_config_defaults(cfg);
    int rc = keyd_read_file(path, 64 * 1024, &text);
    if (rc != KEYD_OK) {
        snprintf(err, err_cap, "cannot read %s: %s", path, keyd_status_str(rc));
        return rc;
    }
    rc = keyd_config_parse(cfg, (const char *)text.data, text.len, err, err_cap);
    keyd_buf_free(&text);
    return rc;
}
