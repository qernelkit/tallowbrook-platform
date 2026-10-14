#include <stdint.h>
#include <string.h>

#include "util/hash_table.h"
#include "keyd/keyd.h"
#include "test.h"

TEST(table_put_get_remove)
{
    struct keyd_table t;
    CHECK(keyd_table_init(&t, 4) == KEYD_OK);
    for (uintptr_t i = 1; i <= 40; i++) {
        char key[16];
        snprintf(key, sizeof key, "label-%lu", (unsigned long)i);
        CHECK(keyd_table_put(&t, key, (void *)i) == KEYD_OK);
    }
    CHECK(t.count == 40);
    CHECK((uintptr_t)keyd_table_get(&t, "label-17") == 17);
    CHECK((uintptr_t)keyd_table_remove(&t, "label-17") == 17);
    CHECK(keyd_table_get(&t, "label-17") == NULL);
    CHECK(t.count == 39);
    keyd_table_free(&t, NULL);
}

TEST(interning_returns_the_same_pointer)
{
    const char *a = keyd_intern("m.okafor");
    const char *b = keyd_intern("m.okafor");
    const char *c = keyd_intern("r.lindqvist");
    CHECK(a != NULL && a == b);
    CHECK(c != NULL && c != a);
    keyd_intern_reset();
}
