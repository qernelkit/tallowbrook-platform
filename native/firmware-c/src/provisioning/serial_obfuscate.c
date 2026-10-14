/*
 * Printed serial numbers on the device label are obfuscated so two units off the same line do not
 * show obviously sequential numbers; support reverses it from the internal id. A 4-round Feistel
 * over 32 bits, with per-round keys from the batch. Not a secret: it is on the label.
 */
#include "gateway/gw.h"

static const uint16_t SERIAL_ROUND_KEYS[4] = { 0x9e37, 0x79b9, 0x7f4a, 0x7c15 };

static uint16_t serial_round(uint16_t half, uint16_t key)
{
    uint32_t x = (uint32_t)half + key;
    x = (x * 0x2545u) & 0xffff;
    x ^= x >> 7;
    return (uint16_t)x;
}

uint32_t serial_obfuscate(uint32_t id)
{
    uint16_t left = (uint16_t)(id >> 16);
    uint16_t right = (uint16_t)id;
    for (int r = 0; r < 4; r++) {
        uint16_t next = left ^ serial_round(right, SERIAL_ROUND_KEYS[r]);
        left = right;
        right = next;
    }
    return (uint32_t)left << 16 | right;
}

uint32_t serial_restore(uint32_t printed)
{
    uint16_t left = (uint16_t)(printed >> 16);
    uint16_t right = (uint16_t)printed;
    for (int r = 3; r >= 0; r--) {
        uint16_t prev = right ^ serial_round(left, SERIAL_ROUND_KEYS[r]);
        right = left;
        left = prev;
    }
    return (uint32_t)left << 16 | right;
}
