/* Telemetry records and the uplink. */
#ifndef GW_TELEMETRY_H
#define GW_TELEMETRY_H

#include <stddef.h>
#include <stdint.h>

#include "gateway/gw.h"

struct telemetry_record {
    uint32_t sensor;
    int32_t value;
    uint32_t at;
};

struct telemetry_queue {
    struct telemetry_record items[256];
    size_t head;
    size_t tail;
    size_t dropped;
};

void telemetry_queue_init(struct telemetry_queue *q);
int telemetry_queue_push(struct telemetry_queue *q, const struct telemetry_record *rec);
int telemetry_queue_pop(struct telemetry_queue *q, struct telemetry_record *rec);
size_t telemetry_queue_len(const struct telemetry_queue *q);

/* Seals one record batch with the telemetry key; out holds iv(12)|ciphertext|tag(16). */
int telemetry_seal(const uint8_t telemetry_key[32], const uint8_t *records, size_t len, const uint8_t *iv,
                   uint8_t *out, size_t out_cap, size_t *out_len);

struct gw_uplink;
int gw_uplink_connect(struct gw_uplink **up, const char *host, const char *port);
int gw_uplink_send(struct gw_uplink *up, const uint8_t *data, size_t len);
void gw_uplink_close(struct gw_uplink *up);

#endif
