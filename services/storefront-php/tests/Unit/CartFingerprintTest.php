<?php

declare(strict_types=1);

namespace Tests\Unit;

use App\Support\Hashing\CartFingerprint;
use PHPUnit\Framework\TestCase;

final class CartFingerprintTest extends TestCase
{
    public function testLineOrderDoesNotMatter(): void
    {
        $a = [['sku' => 'MUG-01', 'qty' => 2], ['sku' => 'TEE-M', 'qty' => 1]];
        $b = [['sku' => 'TEE-M', 'qty' => 1], ['sku' => 'MUG-01', 'qty' => 2]];

        self::assertSame(CartFingerprint::dedupeKey($a), CartFingerprint::dedupeKey($b));
    }

    public function testQuantityChangesTheKey(): void
    {
        self::assertNotSame(
            CartFingerprint::dedupeKey([['sku' => 'MUG-01', 'qty' => 2]]),
            CartFingerprint::dedupeKey([['sku' => 'MUG-01', 'qty' => 3]]),
        );
    }

    public function testBucketsAreStableAndInRange(): void
    {
        $bucket = CartFingerprint::experimentBucket('cus_8812');

        self::assertSame($bucket, CartFingerprint::experimentBucket('cus_8812'));
        self::assertGreaterThanOrEqual(0, $bucket);
        self::assertLessThan(100, $bucket);
    }
}
