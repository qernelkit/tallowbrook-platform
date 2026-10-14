#ifndef VAULTARC_V1_RESTORE_HH
#define VAULTARC_V1_RESTORE_HH

#include <span>
#include <string_view>

#include "vaultarc.hh"

namespace vaultarc {

Bytes restore_v1(std::string_view path, std::string_view passphrase, std::span<const uint8_t> container);

}  // namespace vaultarc

#endif
