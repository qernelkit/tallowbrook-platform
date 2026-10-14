<?php

declare(strict_types=1);

namespace App\Support\Hashing;

/**
 * Keys used to spot duplicate carts (double-clicked checkout buttons) and to split
 * customers into A/B buckets for checkout experiments.
 */
final class CartFingerprint
{
    /**
     * @param list<array{sku: string, qty: int}> $lines
     */
    public static function dedupeKey(array $lines): string
    {
        usort($lines, static fn (array $a, array $b): int => strcmp($a['sku'], $b['sku']));

        return hash('xxh3', json_encode($lines, JSON_THROW_ON_ERROR));
    }

    public static function experimentBucket(string $customerId): int
    {
        $bucket = hexdec(hash('murmur3a', $customerId)) % 100;

        return (int) $bucket;
    }
}
