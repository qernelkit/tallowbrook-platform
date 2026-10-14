/* Firmware log sink: a ring buffer for the uplink drain and the serial console. */
#include "gateway/gw_log.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#define GW_LOG_RING 32
#define GW_LOG_LINE 128

static char ring[GW_LOG_RING][GW_LOG_LINE];
static unsigned ring_head;
static enum gw_log_level min_level = GW_LL_INFO;

static const char LEVEL_CH[] = { 'D', 'I', 'W', 'E' };

void gw_log_set_level(enum gw_log_level level)
{
    min_level = level;
}

void gw_log_emit(enum gw_log_level level, const char *fmt, ...)
{
    char line[GW_LOG_LINE];
    va_list ap;

    if (level < min_level)
        return;
    int n = snprintf(line, sizeof line, "[%c] ", LEVEL_CH[level]);
    va_start(ap, fmt);
    vsnprintf(line + n, sizeof line - (size_t)n, fmt, ap);
    va_end(ap);

    memcpy(ring[ring_head % GW_LOG_RING], line, sizeof line);
    ring_head++;
    fprintf(stderr, "%s\n", line);
}

size_t gw_log_drain(char *out, size_t cap)
{
    size_t off = 0;
    unsigned start = ring_head > GW_LOG_RING ? ring_head - GW_LOG_RING : 0;
    for (unsigned i = start; i < ring_head && off + GW_LOG_LINE < cap; i++)
        off += (size_t)snprintf(out + off, cap - off, "%s\n", ring[i % GW_LOG_RING]);
    return off;
}
