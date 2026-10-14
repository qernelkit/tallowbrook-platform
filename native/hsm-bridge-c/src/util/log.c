#include "util/log.h"

#include <openssl/err.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>

static enum keyd_log_level min_level = KEYD_LOG_INFO;
static int to_syslog;

static const char *const LEVEL_NAMES[] = { "debug", "info", "warn", "error" };
static const int SYSLOG_PRIORITIES[] = { LOG_DEBUG, LOG_INFO, LOG_WARNING, LOG_ERR };

void keyd_log_open(const char *ident, enum keyd_log_level min, int use_syslog)
{
    min_level = min;
    to_syslog = use_syslog;
    if (to_syslog)
        openlog(ident, LOG_PID | LOG_NDELAY, LOG_DAEMON);
}

void keyd_log_set_level(enum keyd_log_level min)
{
    min_level = min;
}

int keyd_log_level_parse(const char *name, enum keyd_log_level *out)
{
    for (size_t i = 0; i < sizeof LEVEL_NAMES / sizeof LEVEL_NAMES[0]; i++) {
        if (strcmp(name, LEVEL_NAMES[i]) == 0) {
            *out = (enum keyd_log_level)i;
            return 0;
        }
    }
    return -1;
}

void keyd_log(enum keyd_log_level level, const char *file, int line, const char *fmt, ...)
{
    char msg[1024];
    va_list ap;

    if (level < min_level)
        return;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof msg, fmt, ap);
    va_end(ap);

    if (to_syslog) {
        syslog(SYSLOG_PRIORITIES[level], "%s", msg);
        return;
    }
    if (level == KEYD_LOG_DEBUG)
        fprintf(stderr, "<%d>%s (%s:%d)\n", SYSLOG_PRIORITIES[level], msg, file, line);
    else
        fprintf(stderr, "<%d>%s\n", SYSLOG_PRIORITIES[level], msg);
}

void log_openssl_errors(const char *what)
{
    unsigned long code;
    char buf[256];
    int n = 0;

    while ((code = ERR_get_error()) != 0) {
        ERR_error_string_n(code, buf, sizeof buf);
        log_err("%s: %s", what, buf);
        n++;
    }
    if (n == 0)
        log_err("%s: failed (no library error queued)", what);
}
