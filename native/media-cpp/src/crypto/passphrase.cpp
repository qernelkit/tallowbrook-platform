// Passphrase-protected archives. Two formats exist in the wild: format 1 used PBKDF2, format 2 uses
// Argon2id. `vaultarc restore` reads both; new archives are always format 2.
#include "crypto/passphrase.hh"

#include <map>

#include <botan/pwdhash.h>

namespace vaultarc {
namespace {
const std::map<int, std::string_view> kPassphraseSchemes = {
    {1, "PBKDF2(SHA-256)"},
    {2, "Argon2id"},
};
constexpr size_t kKeyBytes = 32;
}  // namespace

Bytes derive_passphrase_key(Format format, std::string_view passphrase, std::span<const uint8_t> salt) {
    auto family = Botan::PasswordHashFamily::create_or_throw(kPassphraseSchemes.at(static_cast<int>(format)));
    std::unique_ptr<Botan::PasswordHash> hash;
    if (format == Format::kFormat2)
        hash = family->from_params(65536, 3, 1);
    else
        hash = family->from_iterations(600000);

    Bytes key(kKeyBytes);
    hash->hash(key, passphrase, salt);
    return key;
}

}  // namespace vaultarc
