// Key exchange with the German investigation partner, who requires brainpoolP256r1 under their
// evidence-handling rules. An ephemeral ECDH on that curve, with HKDF-SHA256 over the shared secret.
#include "partner/de_exchange.hh"

#include <botan/auto_rng.h>
#include <botan/ec_group.h>
#include <botan/ecdh.h>
#include <botan/pubkey.h>
#include <botan/x509_key.h>

namespace vaultarc {
namespace {
constexpr std::string_view kPartnerCurve = "brainpool256r1";
constexpr std::string_view kPartnerKeyPath = "/etc/tallowbrook/pki/keys/partner-de-brainpool.pub.pem";
}  // namespace

const char* partner_key_path() {
    return kPartnerKeyPath.data();
}

PartnerExchange exchange_with_partner(std::span<const uint8_t> partner_public, std::span<const uint8_t> info) {
    Botan::AutoSeeded_RNG rng;
    Botan::ECDH_PrivateKey ephemeral(rng, Botan::EC_Group::from_name(kPartnerCurve));

    std::vector<uint8_t> peer(partner_public.begin(), partner_public.end());
    Botan::PK_Key_Agreement agreement(ephemeral, rng, "HKDF(SHA-256)");
    auto shared = agreement.derive_key(32, peer, info.data(), info.size()).bits_of();

    PartnerExchange out;
    out.our_public = ephemeral.subject_public_key();
    out.shared_secret.assign(shared.begin(), shared.end());
    return out;
}

}  // namespace vaultarc
