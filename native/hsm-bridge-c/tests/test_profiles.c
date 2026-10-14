#include <string.h>

#include "keyd/export.h"
#include "test.h"

/* The auditors' tool reads these settings from its own configuration; they must not drift. */
TEST(auditor_profile_matches_the_auditors_tool)
{
    const struct export_profile *p = keyd_export_profile("auditor");
    CHECK(p == &AUDITOR_PROFILE);
    CHECK(p->kdf_iterations == 210000);
    CHECK(p->key_len == 16);
    CHECK(p->iv_len == 16);
    CHECK(strcmp(p->file_suffix, ".tbx") == 0);
}

TEST(unknown_profiles_are_not_found)
{
    CHECK(keyd_export_profile("internal") == NULL);
    CHECK(keyd_export_profile("") == NULL);
    CHECK(keyd_export_profile_count() == 1);
}
