#ifndef VAULTARC_MANIFEST_KEYS_HH
#define VAULTARC_MANIFEST_KEYS_HH

#include <memory>
#include <string>
#include <string_view>

#include <botan/pk_keys.h>

#include "vaultarc.hh"

namespace vaultarc {

std::string generate_manifest_key(std::string_view passphrase);
std::unique_ptr<Botan::Private_Key> load_manifest_key(std::string_view pem, std::string_view passphrase);

}  // namespace vaultarc

#endif
