<?php

declare(strict_types=1);

namespace App\Support;

use InvalidArgumentException;

/**
 * Turns numeric order ids into opaque public references (for emails and tracking links),
 * so customers cannot guess how many orders a merchant takes.
 *
 * The mask comes from ORDER_REF_MASK and must never change once references are out.
 */
final class OrderIdObfuscator
{
    private readonly string $mask;

    public function __construct(?string $mask = null)
    {
        $mask ??= (string) Config::get('services.order_refs.mask', '');
        if (strlen($mask) < 4) {
            throw new InvalidArgumentException('ORDER_REF_MASK must be at least 4 characters');
        }
        $this->mask = $mask;
    }

    public function encode(int $orderId): string
    {
        $plain = pack('J', $orderId);

        return 'TB-' . rtrim(strtr(base64_encode($this->apply($plain)), '+/', '-_'), '=');
    }

    public function decode(string $reference): int
    {
        if (!str_starts_with($reference, 'TB-')) {
            throw new InvalidArgumentException('Not an order reference');
        }
        $raw = base64_decode(strtr(substr($reference, 3), '-_', '+/'), true);
        if ($raw === false || strlen($raw) !== 8) {
            throw new InvalidArgumentException('Malformed order reference');
        }
        $unpacked = unpack('J', $this->apply($raw));
        if ($unpacked === false) {
            throw new InvalidArgumentException('Malformed order reference');
        }

        return (int) $unpacked[1];
    }

    private function apply(string $plain): string
    {
        $out = '';
        for ($i = 0, $n = strlen($plain); $i < $n; $i++) {
            $out .= $plain[$i] ^ $this->mask[$i % strlen($this->mask)];
        }

        return $out;
    }
}
