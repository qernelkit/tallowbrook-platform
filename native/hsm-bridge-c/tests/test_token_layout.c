#include <sodium.h>
#include <string.h>
#include <time.h>

#include "keyd/crypto_api.h"
#include "keyd/keyd.h"
#include "test.h"

static size_t count_char(const char *s, char c)
{
    size_t n = 0;
    for (; *s; s++)
        n += *s == c;
    return n;
}

TEST(enrolment_token_has_three_url_safe_segments)
{
    struct depot d = { .number = 412, .code = "D0412", .region = "north" };
    unsigned char key[32];
    char token[512];

    randombytes_buf(key, sizeof key);
    CHECK(keyd_enrol_token_issue(&d, key, sizeof key, (time_t)1760000000, token, sizeof token) == KEYD_OK);
    CHECK(count_char(token, '.') == 2);
    CHECK(strchr(token, '=') == NULL);
    CHECK(strchr(token, '+') == NULL);
    CHECK(strchr(token, '/') == NULL);
    const char *last = strrchr(token, '.');
    CHECK(last != NULL && strlen(last + 1) == 43);
}

TEST(enrolment_token_needs_room)
{
    struct depot d = { .number = 412, .code = "D0412", .region = "north" };
    unsigned char key[32];
    char token[64];

    randombytes_buf(key, sizeof key);
    CHECK(keyd_enrol_token_issue(&d, key, sizeof key, (time_t)1760000000, token, sizeof token) == KEYD_ERR_ARGS);
}

TEST(same_input_gives_same_token)
{
    struct depot d = { .number = 77, .code = "D0077", .region = "west" };
    unsigned char key[32];
    char a[512], b[512];

    randombytes_buf(key, sizeof key);
    CHECK(keyd_enrol_token_issue(&d, key, sizeof key, (time_t)1760000000, a, sizeof a) == KEYD_OK);
    CHECK(keyd_enrol_token_issue(&d, key, sizeof key, (time_t)1760000000, b, sizeof b) == KEYD_OK);
    CHECK(strcmp(a, b) == 0);
}
