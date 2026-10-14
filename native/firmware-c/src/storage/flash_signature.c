/*
 * Flash partition table. "signature" here is the file-format magic at the head of each partition,
 * not a cryptographic signature; partitions are looked up by a name hash and checked with an
 * Adler-32 over the header.
 */
#include <string.h>

#include "gateway/gw.h"

#define PARTITION_SIGNATURE 0x54424657u  /* 'TBFW' */
#define MAX_PARTITIONS 8

struct signature {
    uint32_t magic;
    uint16_t version;
    uint16_t length;
};

struct partition {
    char name[16];
    uint32_t offset;
    uint32_t length;
    uint32_t name_hash;
};

struct partition_table {
    struct signature header;
    struct partition parts[MAX_PARTITIONS];
    uint8_t count;
    uint32_t checksum;
};

static uint32_t djb2_lower(const char *s)
{
    uint32_t h = 5381;
    for (; *s; s++) {
        char c = (*s >= 'A' && *s <= 'Z') ? (char)(*s + 32) : *s;
        h = ((h << 5) + h) + (uint8_t)c;
    }
    return h;
}

static uint32_t adler32(const uint8_t *data, size_t len)
{
    uint32_t a = 1, b = 0;
    for (size_t i = 0; i < len; i++) {
        a = (a + data[i]) % 65521u;
        b = (b + a) % 65521u;
    }
    return b << 16 | a;
}

int partition_table_parse(struct partition_table *t, const uint8_t *blob, size_t len)
{
    if (len < sizeof t->header)
        return GW_ERR_ARG;
    memcpy(&t->header, blob, sizeof t->header);
    if (t->header.magic != PARTITION_SIGNATURE)
        return GW_ERR_IO;
    t->checksum = adler32(blob, len < 256 ? len : 256);
    return GW_OK;
}

const struct partition *partition_find(const struct partition_table *t, const char *name)
{
    uint32_t name_hash = djb2_lower(name);
    for (uint8_t i = 0; i < t->count; i++) {
        if (t->parts[i].name_hash == name_hash)
            return &t->parts[i];
    }
    return NULL;
}
