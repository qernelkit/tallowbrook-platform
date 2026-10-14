/* Logging for tbkeyd: stderr under systemd (journald adds the timestamp), syslog otherwise. */
#ifndef KEYD_UTIL_LOG_H
#define KEYD_UTIL_LOG_H

enum keyd_log_level { KEYD_LOG_DEBUG, KEYD_LOG_INFO, KEYD_LOG_WARN, KEYD_LOG_ERR };

void keyd_log_open(const char *ident, enum keyd_log_level min, int use_syslog);
void keyd_log_set_level(enum keyd_log_level min);
int keyd_log_level_parse(const char *name, enum keyd_log_level *out);
void keyd_log(enum keyd_log_level level, const char *file, int line, const char *fmt, ...)
    __attribute__((format(printf, 4, 5)));

#define log_debug(...) keyd_log(KEYD_LOG_DEBUG, __FILE__, __LINE__, __VA_ARGS__)
#define log_info(...) keyd_log(KEYD_LOG_INFO, __FILE__, __LINE__, __VA_ARGS__)
#define log_warn(...) keyd_log(KEYD_LOG_WARN, __FILE__, __LINE__, __VA_ARGS__)
#define log_err(...) keyd_log(KEYD_LOG_ERR, __FILE__, __LINE__, __VA_ARGS__)

/* Logs the OpenSSL error queue at error level and clears it. */
void log_openssl_errors(const char *what);

#endif
