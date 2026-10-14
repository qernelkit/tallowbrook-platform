/*
 * Modbus RTU master for the fuel-pump controllers on the depot forecourt bus. Framing and the
 * standard CRC-16 only; no security (the bus is a dedicated RS-485 pair inside the depot).
 */
#include <string.h>

#include "gateway/gw.h"

#define MODBUS_MAX_PDU 253

static uint16_t modbus_crc16(const uint8_t *data, size_t len)
{
    uint16_t crc = 0xFFFF;
    for (size_t i = 0; i < len; i++) {
        crc ^= data[i];
        for (int b = 0; b < 8; b++)
            crc = (crc & 1) ? (crc >> 1) ^ 0xA001 : crc >> 1;
    }
    return crc;
}

int modbus_build_read(uint8_t addr, uint16_t reg, uint16_t count, uint8_t *frame, size_t cap, size_t *len)
{
    if (cap < 8 || count == 0 || count > 125)
        return GW_ERR_ARG;
    frame[0] = addr;
    frame[1] = 0x03;
    frame[2] = (uint8_t)(reg >> 8);
    frame[3] = (uint8_t)reg;
    frame[4] = (uint8_t)(count >> 8);
    frame[5] = (uint8_t)count;
    uint16_t crc = modbus_crc16(frame, 6);
    frame[6] = (uint8_t)crc;
    frame[7] = (uint8_t)(crc >> 8);
    *len = 8;
    return GW_OK;
}

int modbus_check_reply(const uint8_t *frame, size_t len)
{
    if (len < 5 || len > MODBUS_MAX_PDU)
        return GW_ERR_ARG;
    uint16_t crc = modbus_crc16(frame, len - 2);
    uint16_t got = (uint16_t)frame[len - 2] | (uint16_t)frame[len - 1] << 8;
    return crc == got ? GW_OK : GW_ERR_IO;
}
