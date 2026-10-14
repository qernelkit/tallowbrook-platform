#ifndef VAULTARC_TEST_HH
#define VAULTARC_TEST_HH

#include <cstdio>
#include <functional>
#include <string>
#include <vector>

struct TestCase {
    std::string name;
    std::function<void()> fn;
};

std::vector<TestCase>& test_registry();
extern int g_test_failures;

struct TestRegistrar {
    TestRegistrar(const std::string& name, std::function<void()> fn) { test_registry().push_back({name, fn}); }
};

#define TEST(name)                                                       \
    static void name();                                                  \
    static TestRegistrar registrar_##name(#name, name);                  \
    static void name()

#define CHECK(cond)                                                      \
    do {                                                                 \
        if (!(cond)) {                                                   \
            std::fprintf(stderr, "  %s:%d: CHECK(%s) failed\n", __FILE__, __LINE__, #cond); \
            ++g_test_failures;                                           \
        }                                                                \
    } while (0)

#endif
