#ifndef VAULTARC_YEARLY_SEAL_HH
#define VAULTARC_YEARLY_SEAL_HH

#include <cstdint>
#include <span>

#include "vaultarc.hh"

namespace vaultarc {

struct SealKey {
    Bytes private_bytes;
    uint64_t remaining = 0;
};

SealKey new_seal_key();
Bytes seal_year(SealKey& key, std::span<const uint8_t> manifest_digest);

}  // namespace vaultarc

#endif
