// Per-camera session keys are derived from the shared secret the camera enrolment established, with
// HKDF-SHA256 bound to the camera id so each camera gets a distinct key from the same secret. The
// domain-separation salt and info are built from the camera id at run time, not stored.
#include "ingest/camera_keys.hh"

#include <cryptopp/hkdf.h>
#include <cryptopp/sha.h>

namespace vaultarc {

void derive_camera_key(CameraSession& session, std::span<const uint8_t> shared, std::string_view camera_id) {
    const std::string salt = "vaultarc-camera/" + std::string(camera_id);
    const std::string info = "feed-key/" + std::string(camera_id);
    const auto* salt_bytes = reinterpret_cast<const uint8_t*>(salt.data());
    const auto* info_bytes = reinterpret_cast<const uint8_t*>(info.data());

    std::array<uint8_t, 32> key{};
    CryptoPP::HKDF<CryptoPP::SHA256>().DeriveKey(key.data(), key.size(), shared.data(), shared.size(), salt_bytes,
                                                 salt.size(), info_bytes, info.size());
    std::copy(key.begin(), key.end(), session.key);
    session.camera_id = std::string(camera_id);
}

}  // namespace vaultarc
