/* Firmware logging: a ring buffer drained over the uplink, and the serial console in the lab. */
#ifndef GW_LOG_H
#define GW_LOG_H

enum gw_log_level { GW_LL_DEBUG, GW_LL_INFO, GW_LL_WARN, GW_LL_ERR };

void gw_log_emit(enum gw_log_level level, const char *fmt, ...) __attribute__((format(printf, 2, 3)));

#define GW_LOG(...) gw_log_emit(GW_LL_INFO, __VA_ARGS__)
#define GW_LOG_WARN(...) gw_log_emit(GW_LL_WARN, __VA_ARGS__)
#define GW_LOG_ERR(...) gw_log_emit(GW_LL_ERR, __VA_ARGS__)

#endif
