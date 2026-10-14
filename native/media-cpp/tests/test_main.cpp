#include "test.hh"

#include <cstdio>

int g_test_failures = 0;

std::vector<TestCase>& test_registry() {
    static std::vector<TestCase> registry;
    return registry;
}

int main() {
    for (auto& tc : test_registry()) {
        int before = g_test_failures;
        tc.fn();
        std::printf("%s %s\n", g_test_failures == before ? "pass" : "FAIL", tc.name.c_str());
    }
    std::printf("%zu tests, %d failed checks\n", test_registry().size(), g_test_failures);
    return g_test_failures == 0 ? 0 : 1;
}
