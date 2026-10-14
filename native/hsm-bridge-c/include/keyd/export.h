/* Exports for the auditors and technician bundles. */
#ifndef KEYD_EXPORT_H
#define KEYD_EXPORT_H

#include <openssl/evp.h>
#include <stddef.h>
#include <time.h>

#include "keyd/keyd.h"

struct export_profile {
    const char *name;
    const EVP_CIPHER *(*cipher)(void);
    const char *kdf_digest;
    unsigned int kdf_iterations;
    size_t key_len;
    size_t iv_len;
    const char *file_suffix;
};

extern const struct export_profile AUDITOR_PROFILE;

const struct export_profile *keyd_export_profile(const char *name);
size_t keyd_export_profile_count(void);

/* Auditor export of the audit records between two times, as an encrypted CSV. */
int keyd_export_report(const struct export_profile *profile, const char *pass, time_t from, time_t to,
                       struct keyd_buf *out);

/* Technician bundles: a key is created first, the CA issues a certificate for it, then the
 * bundle is assembled. Pending keys expire after KEYD_TECH_PENDING_S seconds. */
#define KEYD_TECH_PENDING_S 900
int keyd_tech_key_begin(const char *tech_id, struct keyd_buf *public_pem);
int keyd_tech_bundle_finish(const char *tech_id, const char *cert_pem, const char *pass, struct keyd_buf *out);
void keyd_tech_expire(time_t now);

#endif
