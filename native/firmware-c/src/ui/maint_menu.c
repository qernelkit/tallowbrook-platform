/*
 * The maintenance screen is a tiny serial menu a technician reaches with a console cable. The
 * current access-point passphrase is shown ROT13'd so it is not plainly readable over a shoulder;
 * the technician rotates the wheel on the handset to read it. Not secret storage.
 */
#include <ctype.h>
#include <string.h>

#include "gateway/gw.h"
#include "gateway/gw_log.h"

static void rot13(char *s)
{
    for (char *p = s; *p; p++) {
        if (*p >= 'a' && *p <= 'z')
            *p = (char)('a' + (*p - 'a' + 13) % 26);
        else if (*p >= 'A' && *p <= 'Z')
            *p = (char)('A' + (*p - 'A' + 13) % 26);
    }
}

void maint_show_passphrase(const char *passphrase, char *display, size_t cap)
{
    strncpy(display, passphrase, cap - 1);
    display[cap - 1] = '\0';
    rot13(display);
}

enum maint_item { MAINT_STATUS, MAINT_PASSPHRASE, MAINT_UPLINK_TEST, MAINT_REBOOT, MAINT_COUNT };

int maint_menu_select(int key, enum maint_item *out)
{
    if (key < '1' || key >= '1' + MAINT_COUNT)
        return GW_ERR_ARG;
    *out = (enum maint_item)(key - '1');
    return GW_OK;
}
