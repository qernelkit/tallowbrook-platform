<?php

declare(strict_types=1);

namespace Tests\Unit;

use App\Support\OrderIdObfuscator;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;

final class OrderIdObfuscatorTest extends TestCase
{
    private OrderIdObfuscator $references;

    protected function setUp(): void
    {
        $this->references = new OrderIdObfuscator(bin2hex(random_bytes(8)));
    }

    public function testRoundTrip(): void
    {
        foreach ([1, 42, 100_000, 987_654_321] as $orderId) {
            self::assertSame($orderId, $this->references->decode($this->references->encode($orderId)));
        }
    }

    public function testReferencesLookLikeOurs(): void
    {
        self::assertStringStartsWith('TB-', $this->references->encode(7));
    }

    public function testRejectsForeignStrings(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->references->decode('ORDER-7');
    }

    public function testRejectsShortMask(): void
    {
        $this->expectException(InvalidArgumentException::class);
        new OrderIdObfuscator('ab');
    }
}
