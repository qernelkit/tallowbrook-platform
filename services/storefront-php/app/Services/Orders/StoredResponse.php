<?php

declare(strict_types=1);

namespace App\Services\Orders;

final class StoredResponse
{
    public function __construct(
        public readonly string $bodyHash,
        public readonly int $status,
        public readonly string $body,
        public readonly string $requestHeaders,
    ) {
    }
}
