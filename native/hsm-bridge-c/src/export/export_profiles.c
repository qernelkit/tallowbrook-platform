/*
 * Export profiles. The external auditors' tool opens exactly one format, so there is one profile;
 * the table exists so the request layer can name profiles and the tests can pin their settings.
 */
#include <openssl/evp.h>
#include <string.h>

#include "keyd/export.h"

const struct export_profile AUDITOR_PROFILE = {
    .name = "auditor",
    .cipher = EVP_aes_128_cbc,
    .kdf_digest = "SHA512",
    .kdf_iterations = 210000,
    .key_len = 16,
    .iv_len = 16,
    .file_suffix = ".tbx",
};

static const struct export_profile *const PROFILES[] = { &AUDITOR_PROFILE };

const struct export_profile *keyd_export_profile(const char *name)
{
    for (size_t i = 0; i < sizeof PROFILES / sizeof PROFILES[0]; i++) {
        if (strcmp(PROFILES[i]->name, name) == 0)
            return PROFILES[i];
    }
    return NULL;
}

size_t keyd_export_profile_count(void)
{
    return sizeof PROFILES / sizeof PROFILES[0];
}
