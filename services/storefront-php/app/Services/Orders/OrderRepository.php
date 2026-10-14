<?php

declare(strict_types=1);

namespace App\Services\Orders;

use App\Models\Order;

interface OrderRepository
{
    public function find(int $orderId): ?Order;

    /**
     * @return list<Order>
     */
    public function forCustomer(string $customerId, int $limit, int $offset): array;

    public function findOpenByCartKey(string $customerId, string $cartKey): ?int;

    /**
     * @param list<array{sku: string, qty: int}> $lines
     */
    public function create(string $customerId, string $merchantId, array $lines, string $cartKey): int;

    public function cancel(int $orderId): void;
}
