// A yearly seal over the whole manifest set, kept as a hash-based signature so the archive's
// integrity proof is not tied to RSA when the review window is measured in years. HSS/LMS is
// stateful: the private key is written back after every signature so a leaf is never reused.
#include "crypto/yearly_seal.hh"

#include <botan/auto_rng.h>
#include <botan/data_src.h>
#include <botan/hss_lms.h>
#include <botan/pkcs8.h>
#include <botan/pubkey.h>

namespace vaultarc {
namespace {
// One LMS layer, SHA-256, tree height 10 (1024 seals), Winternitz w=4.
constexpr std::string_view kSealParams = "SHA-256,HW(10,4)";
}  // namespace

SealKey new_seal_key() {
    Botan::AutoSeeded_RNG rng;
    Botan::HSS_LMS_PrivateKey seal_key(rng, kSealParams);
    SealKey out;
    const auto ber = Botan::PKCS8::BER_encode(seal_key);
    out.private_bytes.assign(ber.begin(), ber.end());
    out.remaining = seal_key.remaining_operations().value_or(0);
    return out;
}

Bytes seal_year(SealKey& key, std::span<const uint8_t> manifest_digest) {
    Botan::AutoSeeded_RNG rng;
    Botan::DataSource_Memory src(key.private_bytes);
    auto loaded = Botan::PKCS8::load_key(src);
    auto* seal_key = dynamic_cast<Botan::HSS_LMS_PrivateKey*>(loaded.get());
    if (seal_key == nullptr)
        throw ArchiveError("seal key is not HSS-LMS");

    Botan::PK_Signer signer(*seal_key, rng, "");
    Bytes sig = signer.sign_message(manifest_digest, rng);

    // Persist the advanced state before the signature is used.
    const auto ber = Botan::PKCS8::BER_encode(*seal_key);
    key.private_bytes.assign(ber.begin(), ber.end());
    key.remaining = seal_key->remaining_operations().value_or(0);
    return sig;
}

}  // namespace vaultarc
