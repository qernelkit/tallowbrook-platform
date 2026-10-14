/* Minimal test harness: TEST(name) registers a function, CHECK records a failure and continues. */
#ifndef KEYD_TEST_H
#define KEYD_TEST_H

#include <stdio.h>

typedef void (*test_fn)(void);
void test_register(const char *name, test_fn fn);
extern int test_failures;

#define TEST(name)                                                                     \
    static void name(void);                                                            \
    __attribute__((constructor)) static void register_##name(void) { test_register(#name, name); } \
    static void name(void)

#define CHECK(cond)                                                                    \
    do {                                                                               \
        if (!(cond)) {                                                                 \
            fprintf(stderr, "  %s:%d: CHECK(%s) failed\n", __FILE__, __LINE__, #cond); \
            test_failures++;                                                           \
        }                                                                              \
    } while (0)

#endif
