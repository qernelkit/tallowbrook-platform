#ifndef VAULTARC_MANIFEST_SIGNER_HH
#define VAULTARC_MANIFEST_SIGNER_HH

#include <span>
#include <string>

#include <botan/pk_keys.h>

#include "vaultarc.hh"

namespace vaultarc {

struct Manifest {
    Bytes body;
    std::string signature_b64;
};

Manifest sign_manifest(const Botan::Private_Key& key, std::span<const uint8_t> body);

}  // namespace vaultarc

#endif
