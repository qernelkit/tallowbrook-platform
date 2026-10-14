// Dedupe buckets. A fast non-cryptographic hash (MurmurHash3 finaliser) picks the bucket for a chunk
// digest; std::hash picks the shard. Neither is used for integrity.
#ifndef VAULTARC_BUCKET_HASH_HH
#define VAULTARC_BUCKET_HASH_HH

#include <cstdint>
#include <string_view>

namespace vaultarc {

inline uint64_t bucket_mix(uint64_t k) {
    k ^= k >> 33;
    k *= 0xff51afd7ed558ccdULL;
    k ^= k >> 33;
    k *= 0xc4ceb9fe1a85ec53ULL;
    k ^= k >> 33;
    return k;
}

inline size_t shard_of(std::string_view clip_id, size_t bucket_count) {
    return std::hash<std::string_view>{}(clip_id) % bucket_count;
}

}  // namespace vaultarc

#endif
