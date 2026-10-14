#include "index/bucket_hash.hh"
#include "index/chunk_index.hh"
#include "test.hh"

using namespace vaultarc;

TEST(chunk_index_deduplicates) {
    ChunkIndex index;
    Bytes a = {1, 2, 3, 4, 5};
    Bytes b = {9, 8, 7, 6};
    CHECK(index.add(a));
    CHECK(!index.add(a));
    CHECK(index.add(b));
    CHECK(index.size() == 2);
}

TEST(chunk_address_is_stable_and_distinct) {
    ChunkIndex index;
    Bytes a = {1, 2, 3};
    Bytes b = {1, 2, 4};
    CHECK(index.address(a) == index.address(a));
    CHECK(index.address(a) != index.address(b));
}

TEST(bucket_mix_and_shard_are_deterministic) {
    CHECK(bucket_mix(12345) == bucket_mix(12345));
    CHECK(shard_of("clip-1", 64) == shard_of("clip-1", 64));
}
