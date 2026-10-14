#ifndef VAULTARC_CHUNK_INDEX_HH
#define VAULTARC_CHUNK_INDEX_HH

#include <array>
#include <span>
#include <string>
#include <vector>

#include "vaultarc.hh"

namespace vaultarc {

class ChunkIndex {
public:
    std::string address(std::span<const uint8_t> chunk) const;
    bool add(std::span<const uint8_t> chunk);
    size_t size() const;

private:
    std::array<std::vector<std::string>, 1024> buckets_;
    size_t count_ = 0;
};

}  // namespace vaultarc

#endif
