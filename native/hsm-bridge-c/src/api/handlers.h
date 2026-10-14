#ifndef KEYD_HANDLERS_H
#define KEYD_HANDLERS_H

#include "config/config.h"
#include "keyd/hsm.h"
#include "keyd/keyd.h"
#include "keyd/link.h"

enum keyd_role { ROLE_NONE, ROLE_GATEWAY, ROLE_SERVICE, ROLE_CONSOLE, ROLE_BACK_OFFICE };

struct keyd_session {
    const char *peer;
    enum keyd_role role;
    struct keyd_p11 *p11;
    const struct keyd_config *cfg;
    struct keyd_link_session *link;
    struct keyd_handheld handheld;
    int handheld_paired;
};

enum keyd_role keyd_role_for_peer(const char *common_name);
void keyd_session_end(struct keyd_session *s);
int keyd_handle_line(struct keyd_session *s, char *line, char *reply, size_t reply_cap);

#endif
