/* Shared types for the depot gateway firmware. */
#ifndef GW_H
#define GW_H

#include <stddef.h>
#include <stdint.h>

enum gw_status {
    GW_OK = 0,
    GW_ERR_ARG = -1,
    GW_ERR_IO = -2,
    GW_ERR_CRYPTO = -3,
    GW_ERR_AUTH = -4,
    GW_ERR_STATE = -5,
    GW_ERR_FULL = -6,
};

static inline uint32_t gw_load_be32(const uint8_t *p)
{
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
}

static inline void gw_store_be32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

#endif
