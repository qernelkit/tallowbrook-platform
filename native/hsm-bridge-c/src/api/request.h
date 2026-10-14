/* Line protocol: "<verb> <arg>...\n", answered by "ok <value>...\n" or "err <code> <message>\n". */
#ifndef KEYD_REQUEST_H
#define KEYD_REQUEST_H

#include <stddef.h>

#define KEYD_MAX_ARGS 8

struct keyd_request {
    char verb[32];
    char *args[KEYD_MAX_ARGS];
    size_t nargs;
    char *line;
};

int keyd_request_parse(char *line, struct keyd_request *req);
const char *keyd_request_arg(const struct keyd_request *req, size_t i);
int keyd_reply_ok(char *out, size_t cap, const char *value);
int keyd_reply_err(char *out, size_t cap, int status, const char *message);

#endif
