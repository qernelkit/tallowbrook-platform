<?php

declare(strict_types=1);

namespace App\Models;

use App\Enums\OrderStatus;
use DateTimeImmutable;

final class Order
{
    /**
     * @param list<OrderLine> $lines
     */
    public function __construct(
        public readonly int $id,
        public readonly string $merchantId,
        public readonly string $customerId,
        public OrderStatus $status,
        public readonly array $lines,
        public readonly string $currency,
        public readonly DateTimeImmutable $placedAt,
        public ?string $trackingNumber = null,
        public ?string $sealedAddress = null,
    ) {
    }

    public function totalMinor(): int
    {
        return array_sum(array_map(static fn (OrderLine $line): int => $line->totalMinor(), $this->lines));
    }

    public function itemCount(): int
    {
        return array_sum(array_map(static fn (OrderLine $line): int => $line->quantity, $this->lines));
    }

    public function canBeCancelled(): bool
    {
        return in_array($this->status, [OrderStatus::Pending, OrderStatus::Paid], true);
    }
}
