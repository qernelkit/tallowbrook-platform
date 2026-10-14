// Drive images for cold storage: AES-256/XTS, the sector cipher, with the sector index as the tweak.
#include "vaultarc.hh"

#include <botan/cipher_mode.h>

namespace vaultarc {
namespace {
constexpr std::string_view kDriveImageCipher = "AES-256/XTS";
}  // namespace

Bytes seal_drive_image(std::span<const uint8_t> plaintext, std::span<const uint8_t> key,
                       std::span<const uint8_t> tweak) {
    auto enc = Botan::Cipher_Mode::create_or_throw(kDriveImageCipher, Botan::Cipher_Dir::Encryption);
    enc->set_key(key.data(), key.size());
    enc->start(tweak.data(), tweak.size());

    Botan::secure_vector<uint8_t> buf(plaintext.begin(), plaintext.end());
    enc->finish(buf);
    return Bytes(buf.begin(), buf.end());
}

}  // namespace vaultarc
