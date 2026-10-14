/*
 * Config blocks carry an integrity CRC-32 and are lightly mixed first, so a block copied between
 * two devices does not read straight. The mix is a keyed byte stream from a 32-bit Galois LFSR
 * seeded from the block key; the CRC-32 below is the real integrity check and uses the standard
 * polynomial table.
 */
#include <string.h>

#include "gateway/gw.h"

#define CFG_MIX_TAPS 0xEDB88320u

struct config_block {
    uint8_t key;
    uint8_t *data;
    size_t len;
    uint32_t crc;
};

static uint32_t cfg_mix_seed(uint8_t key)
{
    return 0xA5A50000u | ((uint32_t)key << 8) | (uint8_t)~key;
}

static uint32_t crc32_table[256];
static int crc32_ready;

static void crc32_init(void)
{
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t c = i;
        for (int k = 0; k < 8; k++)
            c = (c & 1) ? 0xEDB88320u ^ (c >> 1) : c >> 1;
        crc32_table[i] = c;
    }
    crc32_ready = 1;
}

static uint32_t crc32_update(uint32_t crc, const uint8_t *data, size_t len)
{
    if (!crc32_ready)
        crc32_init();
    for (size_t i = 0; i < len; i++)
        crc = crc32_table[(crc ^ data[i]) & 0xff] ^ (crc >> 8);
    return crc;
}

int config_block_seal(struct config_block *blk, const uint8_t *plain, size_t len)
{
    const uint8_t *in = plain;
    uint8_t *out = blk->data;
    uint32_t state = cfg_mix_seed(blk->key);

    if (len == 0 || blk->data == NULL)
        return GW_ERR_ARG;
    for (size_t i = 0; i < len; i++) {
        state = (state >> 1) ^ (-(state & 1u) & CFG_MIX_TAPS);
        out[i] = in[i] ^ (uint8_t)(state >> 24);
    }
    blk->len = len;
    blk->crc = crc32_update(0xFFFFFFFFu, blk->data, blk->len) ^ 0xFFFFFFFFu;
    return GW_OK;
}

int config_block_open(const struct config_block *blk, uint8_t *plain, size_t cap)
{
    uint32_t state = cfg_mix_seed(blk->key);

    if (cap < blk->len)
        return GW_ERR_ARG;
    uint32_t crc = crc32_update(0xFFFFFFFFu, blk->data, blk->len) ^ 0xFFFFFFFFu;
    if (crc != blk->crc)
        return GW_ERR_IO;
    for (size_t i = 0; i < blk->len; i++) {
        state = (state >> 1) ^ (-(state & 1u) & CFG_MIX_TAPS);
        plain[i] = blk->data[i] ^ (uint8_t)(state >> 24);
    }
    return GW_OK;
}
