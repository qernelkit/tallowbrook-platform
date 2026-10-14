#include "gateway/gw.h"
#include "test.h"

int modbus_build_read(uint8_t addr, uint16_t reg, uint16_t count, uint8_t *frame, size_t cap, size_t *len);
int modbus_check_reply(const uint8_t *frame, size_t len);

TEST(modbus_read_frame_has_valid_crc)
{
    uint8_t frame[8];
    size_t len = 0;
    CHECK(modbus_build_read(0x11, 0x006B, 3, frame, sizeof frame, &len) == GW_OK);
    CHECK(len == 8);
    /* The frame we just built must pass the receiver's own CRC check. */
    CHECK(modbus_check_reply(frame, len) == GW_OK);
}

TEST(modbus_rejects_corrupted_frames)
{
    uint8_t frame[8];
    size_t len = 0;
    modbus_build_read(0x11, 0x006B, 3, frame, sizeof frame, &len);
    frame[2] ^= 0xff;
    CHECK(modbus_check_reply(frame, len) == GW_ERR_IO);
}
