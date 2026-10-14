#include <string.h>

#include "gateway/gw.h"
#include "test.h"

uint32_t serial_obfuscate(uint32_t id);
uint32_t serial_restore(uint32_t printed);
void eeprom_scramble_page(uint8_t *out, const uint8_t *in, size_t len, uint8_t page);
void eeprom_unscramble_page(uint8_t *out, const uint8_t *in, size_t len, uint8_t page);

TEST(serial_obfuscation_round_trips)
{
    for (uint32_t id = 1; id < 5000; id += 137) {
        uint32_t printed = serial_obfuscate(id);
        CHECK(serial_restore(printed) == id);
    }
    CHECK(serial_obfuscate(1234) != 1234);
}

TEST(eeprom_scramble_round_trips_and_changes_bytes)
{
    uint8_t in[32], scrambled[32], back[32];
    for (int i = 0; i < 32; i++)
        in[i] = (uint8_t)(i * 7 + 1);
    eeprom_scramble_page(scrambled, in, sizeof in, 3);
    CHECK(memcmp(scrambled, in, sizeof in) != 0);
    eeprom_unscramble_page(back, scrambled, sizeof scrambled, 3);
    CHECK(memcmp(back, in, sizeof in) == 0);
}
