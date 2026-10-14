/* Bounded ring buffer of telemetry records with drop accounting. No crypto here. */
#include <string.h>

#include "gateway/telemetry.h"

#define QUEUE_CAP (sizeof(((struct telemetry_queue *)0)->items) / sizeof(struct telemetry_record))

void telemetry_queue_init(struct telemetry_queue *q)
{
    memset(q, 0, sizeof *q);
}

size_t telemetry_queue_len(const struct telemetry_queue *q)
{
    return (q->head + QUEUE_CAP - q->tail) % QUEUE_CAP;
}

int telemetry_queue_push(struct telemetry_queue *q, const struct telemetry_record *rec)
{
    size_t next = (q->head + 1) % QUEUE_CAP;
    if (next == q->tail) {
        q->dropped++;
        q->tail = (q->tail + 1) % QUEUE_CAP;
    }
    q->items[q->head] = *rec;
    q->head = next;
    return GW_OK;
}

int telemetry_queue_pop(struct telemetry_queue *q, struct telemetry_record *rec)
{
    if (q->head == q->tail)
        return GW_ERR_STATE;
    *rec = q->items[q->tail];
    q->tail = (q->tail + 1) % QUEUE_CAP;
    return GW_OK;
}
