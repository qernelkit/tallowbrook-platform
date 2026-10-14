#ifndef VAULTARC_PASSPHRASE_HH
#define VAULTARC_PASSPHRASE_HH

#include <span>
#include <string_view>

#include "vaultarc.hh"

namespace vaultarc {

Bytes derive_passphrase_key(Format format, std::string_view passphrase, std::span<const uint8_t> salt);

}  // namespace vaultarc

#endif
