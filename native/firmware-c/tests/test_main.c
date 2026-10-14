#include <stdio.h>
#include <string.h>

#include "test.h"

#define MAX_TESTS 128
int test_failures;
static struct { const char *name; test_fn fn; } tests[MAX_TESTS];
static int ntests;

void test_register(const char *name, test_fn fn)
{
    if (ntests < MAX_TESTS) {
        tests[ntests].name = name;
        tests[ntests].fn = fn;
        ntests++;
    }
}

int main(void)
{
    for (int i = 0; i < ntests; i++) {
        int before = test_failures;
        tests[i].fn();
        printf("%s %s\n", test_failures == before ? "pass" : "FAIL", tests[i].name);
    }
    printf("%d tests, %d failed checks\n", ntests, test_failures);
    return test_failures == 0 ? 0 : 1;
}
