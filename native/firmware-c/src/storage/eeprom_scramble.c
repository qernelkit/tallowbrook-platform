/*
 * The config EEPROM is a cheap external part that is easy to read off the board, so pages are
 * scrambled before they are written. This is obfuscation against a casual reader with a bus pirate,
 * not a security boundary; the real secrets live in the secure element.
 */
#include <string.h>

#include "gateway/gw.h"

/* Per-device mask, mixed from the part serial at provisioning time. */
static const uint8_t EEPROM_MASK[16] = { 0x3f, 0xa1, 0x08, 0xd4, 0x9c, 0x27, 0x6b, 0xe0, 0x55, 0x12, 0xbe, 0x7a, 0xc3, 0x4d, 0x90, 0xf8 };

void eeprom_scramble_page(uint8_t *out, const uint8_t *in, size_t len, uint8_t page)
{
    for (size_t i = 0; i < len; i++)
        out[i] = in[i] ^ EEPROM_MASK[(i + page) % sizeof EEPROM_MASK];
}

void eeprom_unscramble_page(uint8_t *out, const uint8_t *in, size_t len, uint8_t page)
{
    eeprom_scramble_page(out, in, len, page);
}
