/*
 * A/B slot bookkeeping: which slot is active, which is staged, and a one-shot "try" flag so a bad
 * update rolls back after a failed boot. No crypto.
 */
#include <string.h>

#include "gateway/gw.h"
#include "gateway/gw_log.h"

enum slot_state { SLOT_GOOD = 0, SLOT_STAGED = 1, SLOT_TRY = 2, SLOT_BAD = 3 };

struct slot_table {
    char active;         /* 'A' or 'B' */
    enum slot_state state[2];
    uint32_t build[2];
    uint8_t boot_attempts;
};

static int slot_index(char slot)
{
    return slot == 'B' ? 1 : 0;
}

void slot_table_init(struct slot_table *t)
{
    memset(t, 0, sizeof *t);
    t->active = 'A';
    t->state[0] = SLOT_GOOD;
    t->state[1] = SLOT_BAD;
}

int slot_stage(struct slot_table *t, uint32_t build)
{
    int spare = t->active == 'A' ? 1 : 0;
    t->state[spare] = SLOT_STAGED;
    t->build[spare] = build;
    GW_LOG("slot: staged build %u on slot %c", build, spare == 1 ? 'B' : 'A');
    return GW_OK;
}

int slot_switch(struct slot_table *t)
{
    int spare = t->active == 'A' ? 1 : 0;
    if (t->state[spare] != SLOT_STAGED)
        return GW_ERR_STATE;
    t->state[spare] = SLOT_TRY;
    t->active = spare == 1 ? 'B' : 'A';
    t->boot_attempts = 0;
    return GW_OK;
}

int slot_confirm(struct slot_table *t)
{
    int i = slot_index(t->active);
    if (t->state[i] == SLOT_TRY) {
        t->state[i] = SLOT_GOOD;
        GW_LOG("slot: build %u on slot %c confirmed", t->build[i], t->active);
    }
    return GW_OK;
}

int slot_rollback(struct slot_table *t)
{
    int i = slot_index(t->active);
    t->state[i] = SLOT_BAD;
    t->active = t->active == 'A' ? 'B' : 'A';
    GW_LOG_WARN("slot: rolled back to slot %c", t->active);
    return GW_OK;
}
