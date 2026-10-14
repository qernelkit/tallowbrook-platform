/* Front-panel keypad: scan codes and auto-repeat. "KEY" here is a keypad key, not crypto. */
#include "gateway/gw.h"

#define KEY_ESCAPE 27
#define KEY_ENTER 13
#define KEY_UP 'A'
#define KEY_DOWN 'B'
#define KEY_REPEAT_MS 250

struct keypad {
    int last_code;
    uint32_t held_ms;
    int repeating;
};

void keypad_init(struct keypad *k)
{
    k->last_code = 0;
    k->held_ms = 0;
    k->repeating = 0;
}

int keypad_feed(struct keypad *k, int code, uint32_t dt_ms)
{
    if (code != k->last_code) {
        k->last_code = code;
        k->held_ms = 0;
        k->repeating = 0;
        return code;
    }
    if (code == 0)
        return 0;
    k->held_ms += dt_ms;
    if (k->held_ms >= KEY_REPEAT_MS) {
        k->held_ms = 0;
        k->repeating = 1;
        return code;
    }
    return 0;
}

int keypad_is_escape(int code)
{
    return code == KEY_ESCAPE;
}
