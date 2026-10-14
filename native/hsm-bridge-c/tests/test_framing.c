#include <string.h>

#include "api/handlers.h"
#include "api/request.h"
#include "keyd/keyd.h"
#include "test.h"

TEST(request_parses_verb_and_args)
{
    char line[] = "gate-pass TB12XKR D0412 7 1760000000 1760003600\n";
    struct keyd_request req;
    CHECK(keyd_request_parse(line, &req) == KEYD_OK);
    CHECK(strcmp(req.verb, "gate-pass") == 0);
    CHECK(req.nargs == 5);
    CHECK(strcmp(keyd_request_arg(&req, 0), "TB12XKR") == 0);
    CHECK(strcmp(keyd_request_arg(&req, 4), "1760003600") == 0);
    CHECK(keyd_request_arg(&req, 5) == NULL);
}

TEST(request_rejects_bad_verbs)
{
    char upper[] = "GATE-PASS x";
    char empty[] = "\n";
    char digits[] = "wrap2 x";
    struct keyd_request req;
    CHECK(keyd_request_parse(upper, &req) != KEYD_OK);
    CHECK(keyd_request_parse(empty, &req) != KEYD_OK);
    CHECK(keyd_request_parse(digits, &req) != KEYD_OK);
}

TEST(request_limits_argument_count)
{
    char line[] = "barrier a b c d e f g h i";
    struct keyd_request req;
    CHECK(keyd_request_parse(line, &req) == KEYD_ERR_ARGS);
}

TEST(replies_are_single_lines)
{
    char out[64];
    CHECK(keyd_reply_ok(out, sizeof out, "abc") == 7);
    CHECK(strcmp(out, "ok abc\n") == 0);
    CHECK(keyd_reply_ok(out, sizeof out, NULL) == 3);
    CHECK(keyd_reply_err(out, sizeof out, KEYD_ERR_AUTH, NULL) > 0);
    CHECK(strcmp(out, "err 6 not authorised\n") == 0);
    CHECK(keyd_reply_ok(out, 4, "too long") < 0);
}

TEST(roles_follow_certificate_prefixes)
{
    CHECK(keyd_role_for_peer("gw-d0412") == ROLE_GATEWAY);
    CHECK(keyd_role_for_peer("svc-billing") == ROLE_SERVICE);
    CHECK(keyd_role_for_peer("ops-console-2") == ROLE_CONSOLE);
    CHECK(keyd_role_for_peer("bo-fuel") == ROLE_BACK_OFFICE);
    CHECK(keyd_role_for_peer("gateway") == ROLE_NONE);
}

TEST(unknown_verbs_and_wrong_roles_are_refused)
{
    struct keyd_session s = { .peer = "gw-d0412", .role = ROLE_GATEWAY };
    char line1[] = "no-such-verb";
    char line2[] = "partner-key acme";
    char reply[128];
    CHECK(keyd_handle_line(&s, line1, reply, sizeof reply) > 0);
    CHECK(strncmp(reply, "err 1 ", 6) == 0);
    CHECK(keyd_handle_line(&s, line2, reply, sizeof reply) > 0);
    CHECK(strcmp(reply, "err 6 not authorised\n") == 0);
}
