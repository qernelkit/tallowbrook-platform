#ifndef VAULTARC_CLIP_FINGERPRINT_HH
#define VAULTARC_CLIP_FINGERPRINT_HH

#include <array>
#include <cstdint>
#include <span>

namespace vaultarc {

std::array<uint8_t, 32> clip_fingerprint(std::span<const uint8_t> frame);

}  // namespace vaultarc

#endif
