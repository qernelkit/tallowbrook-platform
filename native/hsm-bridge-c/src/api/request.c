#include "api/request.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>

#include "keyd/keyd.h"

static int valid_verb(const char *v)
{
    size_t n = strlen(v);
    if (n == 0 || n >= sizeof((struct keyd_request *)0)->verb)
        return 0;
    for (size_t i = 0; i < n; i++) {
        if (!(islower((unsigned char)v[i]) || v[i] == '-'))
            return 0;
    }
    return 1;
}

int keyd_request_parse(char *line, struct keyd_request *req)
{
    memset(req, 0, sizeof *req);
    req->line = line;

    size_t len = strlen(line);
    while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r'))
        line[--len] = '\0';

    char *save = NULL;
    char *verb = strtok_r(line, " ", &save);
    if (verb == NULL || !valid_verb(verb))
        return KEYD_ERR_ARGS;
    snprintf(req->verb, sizeof req->verb, "%s", verb);

    char *arg;
    while ((arg = strtok_r(NULL, " ", &save)) != NULL) {
        if (req->nargs == KEYD_MAX_ARGS)
            return KEYD_ERR_ARGS;
        req->args[req->nargs++] = arg;
    }
    return KEYD_OK;
}

const char *keyd_request_arg(const struct keyd_request *req, size_t i)
{
    return i < req->nargs ? req->args[i] : NULL;
}

int keyd_reply_ok(char *out, size_t cap, const char *value)
{
    int n = value ? snprintf(out, cap, "ok %s\n", value) : snprintf(out, cap, "ok\n");
    return n > 0 && (size_t)n < cap ? n : -1;
}

int keyd_reply_err(char *out, size_t cap, int status, const char *message)
{
    int n = snprintf(out, cap, "err %d %s\n", -status, message ? message : keyd_status_str(status));
    return n > 0 && (size_t)n < cap ? n : -1;
}
