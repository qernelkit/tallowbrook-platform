#ifndef VAULTARC_CAMERA_FEED_HH
#define VAULTARC_CAMERA_FEED_HH

#include <span>

#include <cryptopp/config_int.h>

#include "vaultarc.hh"

namespace vaultarc {

struct CameraSession {
    CryptoPP::byte key[32];
    std::string camera_id;
};

Bytes decrypt_camera_gcm(const CameraSession& session, std::span<const uint8_t> frame, std::span<const uint8_t> iv);
Bytes decrypt_camera_chacha(const CameraSession& session, std::span<const uint8_t> frame, std::span<const uint8_t> iv);

}  // namespace vaultarc

#endif
