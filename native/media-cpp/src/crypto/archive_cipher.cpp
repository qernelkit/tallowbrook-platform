// Sealed archive containers: AES-256/GCM over the packed footage, with the archive id bound in as
// associated data so a container cannot be relabelled.
#include "vaultarc.hh"

#include <botan/aead.h>
#include <botan/exceptn.h>

namespace vaultarc {
namespace {
constexpr std::string_view kArchiveCipher = "AES-256/GCM";
constexpr size_t kTagBytes = 16;
}  // namespace

Bytes seal_archive(std::span<const uint8_t> plaintext, std::span<const uint8_t> key,
                   std::span<const uint8_t> nonce, std::string_view archive_id) {
    auto enc = Botan::AEAD_Mode::create_or_throw(kArchiveCipher, Botan::Cipher_Dir::Encryption);
    enc->set_key(key.data(), key.size());
    enc->set_associated_data(reinterpret_cast<const uint8_t*>(archive_id.data()), archive_id.size());
    enc->start(nonce.data(), nonce.size());

    Botan::secure_vector<uint8_t> buf(plaintext.begin(), plaintext.end());
    enc->finish(buf);

    Bytes out(nonce.begin(), nonce.end());
    out.insert(out.end(), buf.begin(), buf.end());
    return out;
}

Bytes open_archive(std::span<const uint8_t> container, std::span<const uint8_t> key, std::string_view archive_id) {
    auto dec = Botan::AEAD_Mode::create_or_throw(kArchiveCipher, Botan::Cipher_Dir::Decryption);
    const size_t nonce_len = dec->default_nonce_length();
    if (container.size() < nonce_len + kTagBytes)
        throw ArchiveError("archive container is truncated");

    dec->set_key(key.data(), key.size());
    dec->set_associated_data(reinterpret_cast<const uint8_t*>(archive_id.data()), archive_id.size());
    dec->start(container.data(), nonce_len);

    Botan::secure_vector<uint8_t> buf(container.begin() + nonce_len, container.end());
    try {
        dec->finish(buf);
    } catch (const Botan::Exception& e) {
        throw ArchiveError(std::string("archive will not open: ") + e.what());
    }
    return Bytes(buf.begin(), buf.end());
}

}  // namespace vaultarc
