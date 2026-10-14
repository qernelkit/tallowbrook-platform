// Camera ingest. Cameras encrypt their feed to the NVR; vaultarc decrypts it and re-seals it for the
// archive. Cameras with an AES engine use AES-128/GCM; the cheaper models without one use
// ChaCha20-Poly1305. Crypto++ on both paths.
#include "ingest/camera_feed.hh"

#include <cryptopp/aes.h>
#include <cryptopp/chachapoly.h>
#include <cryptopp/filters.h>
#include <cryptopp/gcm.h>

namespace vaultarc {

Bytes decrypt_camera_gcm(const CameraSession& session, std::span<const uint8_t> frame, std::span<const uint8_t> iv) {
    CryptoPP::GCM<CryptoPP::AES>::Encryption enc;
    enc.SetKeyWithIV(session.key, CryptoPP::AES::DEFAULT_KEYLENGTH, iv.data(), iv.size());

    std::string out;
    CryptoPP::AuthenticatedEncryptionFilter filter(enc, new CryptoPP::StringSink(out), false, 16);
    filter.Put(frame.data(), frame.size());
    filter.MessageEnd();
    return Bytes(out.begin(), out.end());
}

Bytes decrypt_camera_chacha(const CameraSession& session, std::span<const uint8_t> frame, std::span<const uint8_t> iv) {
    CryptoPP::ChaCha20Poly1305::Encryption aead;
    aead.SetKeyWithIV(session.key, 32, iv.data(), iv.size());

    std::string out;
    CryptoPP::AuthenticatedEncryptionFilter filter(aead, new CryptoPP::StringSink(out), false, 16);
    filter.Put(frame.data(), frame.size());
    filter.MessageEnd();
    return Bytes(out.begin(), out.end());
}

}  // namespace vaultarc
