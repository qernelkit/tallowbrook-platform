// Archive manifests are signed with RSA-PSS(SHA-256). The signature is stored base64 in the manifest
// header; archive_reader.cpp verifies it on open.
#include "crypto/manifest_signer.hh"

#include <botan/auto_rng.h>
#include <botan/base64.h>
#include <botan/pubkey.h>

namespace vaultarc {

Manifest sign_manifest(const Botan::Private_Key& key, std::span<const uint8_t> body) {
    Botan::AutoSeeded_RNG rng;
    Botan::PK_Signer signer(key, rng, "PSS(SHA-256)");

    Manifest manifest;
    manifest.signature_b64 = Botan::base64_encode(signer.sign_message(body, rng));
    manifest.body.assign(body.begin(), body.end());
    return manifest;
}

}  // namespace vaultarc
