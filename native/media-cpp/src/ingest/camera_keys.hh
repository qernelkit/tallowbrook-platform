#ifndef VAULTARC_CAMERA_KEYS_HH
#define VAULTARC_CAMERA_KEYS_HH

#include <span>
#include <string_view>

#include "ingest/camera_feed.hh"

namespace vaultarc {

void derive_camera_key(CameraSession& session, std::span<const uint8_t> shared, std::string_view camera_id);

}  // namespace vaultarc

#endif
