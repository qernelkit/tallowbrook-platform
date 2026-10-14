/*
 * Stage-1 entry: parse the image header, check the magic and the embedded digest, hand control to
 * the next stage. In the product this is the reset vector; here it is a plain function the tests
 * drive.
 */
#include "stage1.h"

#include <string.h>

#define STAGE1_MAGIC 0x54423153u /* 'TB1S' */

int stage1_parse_header(const uint8_t *blob, size_t len, struct stage1_header *out)
{
    if (len < 44)
        return -1;
    out->magic = (uint32_t)blob[0] << 24 | (uint32_t)blob[1] << 16 | (uint32_t)blob[2] << 8 | blob[3];
    out->load_addr = (uint32_t)blob[4] << 24 | (uint32_t)blob[5] << 16 | (uint32_t)blob[6] << 8 | blob[7];
    out->length = (uint32_t)blob[8] << 24 | (uint32_t)blob[9] << 16 | (uint32_t)blob[10] << 8 | blob[11];
    memcpy(out->digest, blob + 12, 32);
    return out->magic == STAGE1_MAGIC ? 0 : -1;
}

int stage1_verify_next(const uint8_t *image, size_t len, const struct stage1_header *hdr)
{
    uint8_t digest[32];
    if (len != hdr->length)
        return -1;
    stage1_sha256(image, len, digest);
    return memcmp(digest, hdr->digest, 32) == 0 ? 0 : -1;
}
