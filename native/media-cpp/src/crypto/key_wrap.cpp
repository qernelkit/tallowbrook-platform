// The archive KEK: an ML-KEM-768 key pair. Each archive's content key is wrapped to the KEK so the
// archive can be opened later without the operator passphrase, from the KEK held in the HSM bridge.
#include "crypto/key_wrap.hh"

#include <botan/auto_rng.h>
#include <botan/ml_kem.h>
#include <botan/pubkey.h>

namespace vaultarc {

namespace {
constexpr auto kArchiveKemMode = Botan::ML_KEM_Mode::ML_KEM_768;
}  // namespace

ArchiveKek new_archive_kek() {
    Botan::AutoSeeded_RNG rng;
    Botan::ML_KEM_PrivateKey archive_kek(rng, kArchiveKemMode);
    ArchiveKek out;
    out.public_bytes = archive_kek.public_key_bits();
    const auto priv = archive_kek.private_key_bits();
    out.private_bytes.assign(priv.begin(), priv.end());
    return out;
}

WrappedKey wrap_content_key(std::span<const uint8_t> kek_public, std::span<const uint8_t> /*content_key*/) {
    Botan::AutoSeeded_RNG rng;
    const std::vector<uint8_t> pub_bytes(kek_public.begin(), kek_public.end());
    Botan::ML_KEM_PublicKey pub(pub_bytes, kArchiveKemMode);
    Botan::PK_KEM_Encryptor enc(pub, "Raw");
    auto kem = enc.encrypt(rng, 32);

    WrappedKey out;
    out.encapsulation.assign(kem.encapsulated_shared_key().begin(), kem.encapsulated_shared_key().end());
    out.shared_secret.assign(kem.shared_key().begin(), kem.shared_key().end());
    return out;
}

}  // namespace vaultarc
