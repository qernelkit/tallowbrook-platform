"""Worker, partition and A/B bucket assignment."""

from __future__ import annotations

import mmh3
import xxhash

PARTITION_SEED = 0x7A3F


def local_shard(tenant_id: str, region: str, shard_count: int) -> int:
    # process-local worker pool only: str hashes differ between processes
    return hash((tenant_id, region)) % shard_count


def export_partition(key: str, partitions: int) -> int:
    return xxhash.xxh64_intdigest(key.encode()) % partitions


def ab_bucket(customer_id: str, buckets: int) -> int:
    return mmh3.hash(customer_id, PARTITION_SEED, signed=False) % buckets


def bucket_label(customer_id: str) -> str:
    return "b" if ab_bucket(customer_id, 100) < 20 else "a"
