<?php

declare(strict_types=1);

namespace App\Models;

use DateTimeImmutable;

final class GiftCard
{
    public function __construct(
        public readonly string $code,
        public readonly string $merchantId,
        public int $balanceMinor,
        public readonly string $currency,
        public readonly DateTimeImmutable $expiresAt,
        public ?string $pinHash = null,
    ) {
    }

    public function isExpired(DateTimeImmutable $now): bool
    {
        return $now >= $this->expiresAt;
    }

    public function redeem(int $amountMinor): int
    {
        $used = min($amountMinor, $this->balanceMinor);
        $this->balanceMinor -= $used;

        return $used;
    }
}
