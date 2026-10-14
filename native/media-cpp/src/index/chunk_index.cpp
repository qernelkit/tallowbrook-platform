// Content-defined chunk index for dedupe. Each chunk is addressed by a digest whose algorithm is
// fixed at build time (VAULTARC_CHUNK_HASH), so a store written by one release stays readable by the
// next. Botan for the hash; bucket_hash.hh for the in-memory bucketing.
#include "index/chunk_index.hh"

#include <botan/hash.h>
#include <botan/hex.h>

#include "index/bucket_hash.hh"

#ifndef VAULTARC_CHUNK_HASH
#error "VAULTARC_CHUNK_HASH is set by the build"
#endif

namespace vaultarc {

std::string ChunkIndex::address(std::span<const uint8_t> chunk) const {
    auto hash = Botan::HashFunction::create_or_throw(VAULTARC_CHUNK_HASH);
    hash->update(chunk.data(), chunk.size());
    return Botan::hex_encode(hash->final());
}

bool ChunkIndex::add(std::span<const uint8_t> chunk) {
    std::string key = address(chunk);
    uint64_t mixed = bucket_mix(std::hash<std::string>{}(key));
    size_t bucket = mixed % buckets_.size();
    auto& list = buckets_[bucket];
    for (const auto& seen : list) {
        if (seen == key)
            return false;
    }
    list.push_back(std::move(key));
    ++count_;
    return true;
}

size_t ChunkIndex::size() const {
    return count_;
}

}  // namespace vaultarc
