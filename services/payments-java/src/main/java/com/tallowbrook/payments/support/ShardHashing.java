package com.tallowbrook.payments.support;

import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/** Spreads merchants and routing keys over database shards and worker slots. */
@Component
public class ShardHashing {

    private static final int SLOTS = 1024;

    private final Map<String, Integer> pinnedShards = new HashMap<>();

    /** Ops can move a very large merchant onto its own shard. */
    public synchronized void pin(String merchantId, int shard) {
        pinnedShards.put(merchantId, shard);
    }

    public synchronized int bucketFor(String key, int buckets) {
        Integer pinned = pinnedShards.get(key);
        if (pinned != null) {
            return pinned;
        }
        return Math.floorMod(key.hashCode(), buckets);
    }

    public int slotFor(byte[] routingKey) {
        int slot = Arrays.hashCode(routingKey) & (SLOTS - 1);
        return slot;
    }
}
