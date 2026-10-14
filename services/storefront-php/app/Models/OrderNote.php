<?php

declare(strict_types=1);

namespace App\Models;

use DateTimeImmutable;

final class OrderNote
{
    public function __construct(
        public readonly int $orderId,
        public readonly string $author,
        public readonly string $body,
        public readonly DateTimeImmutable $writtenAt,
    ) {
    }
}
