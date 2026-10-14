<?php

declare(strict_types=1);

namespace App\Models;

final class OrderLine
{
    public function __construct(
        public readonly string $sku,
        public readonly string $title,
        public readonly int $quantity,
        public readonly int $unitPriceMinor,
    ) {
    }

    public function totalMinor(): int
    {
        return $this->quantity * $this->unitPriceMinor;
    }
}
