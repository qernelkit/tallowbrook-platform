#include <stdio.h>
#include <string.h>

#include "test.h"

#define MAX_TESTS 128

int test_failures;

static struct {
    const char *name;
    test_fn fn;
} tests[MAX_TESTS];
static int ntests;

void test_register(const char *name, test_fn fn)
{
    if (ntests < MAX_TESTS) {
        tests[ntests].name = name;
        tests[ntests].fn = fn;
        ntests++;
    }
}

int main(int argc, char **argv)
{
    const char *only = argc > 1 ? argv[1] : NULL;
    int run = 0;
    for (int i = 0; i < ntests; i++) {
        if (only != NULL && strstr(tests[i].name, only) == NULL)
            continue;
        int before = test_failures;
        tests[i].fn();
        printf("%s %s\n", test_failures == before ? "pass" : "FAIL", tests[i].name);
        run++;
    }
    printf("%d tests, %d failed checks\n", run, test_failures);
    return test_failures == 0 ? 0 : 1;
}
