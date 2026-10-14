<?php

declare(strict_types=1);

namespace App\Services\Orders;

interface IdempotencyStore
{
    public function find(string $key): ?StoredResponse;

    public function save(string $key, StoredResponse $response, int $ttl = 86400): void;
}
