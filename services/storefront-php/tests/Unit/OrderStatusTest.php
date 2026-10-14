<?php

declare(strict_types=1);

namespace Tests\Unit;

use App\Enums\OrderStatus;
use App\Models\Order;
use App\Models\OrderLine;
use DateTimeImmutable;
use PHPUnit\Framework\TestCase;

final class OrderStatusTest extends TestCase
{
    public function testOpenStatuses(): void
    {
        self::assertTrue(OrderStatus::Paid->isOpen());
        self::assertFalse(OrderStatus::Delivered->isOpen());
        self::assertFalse(OrderStatus::Cancelled->isOpen());
    }

    public function testOnlyUnpackedOrdersCanBeCancelled(): void
    {
        $order = $this->order(OrderStatus::Paid);
        self::assertTrue($order->canBeCancelled());

        $order->status = OrderStatus::Packed;
        self::assertFalse($order->canBeCancelled());
    }

    public function testTotals(): void
    {
        $order = $this->order(OrderStatus::Pending);

        self::assertSame(3, $order->itemCount());
        self::assertSame(2 * 1250 + 899, $order->totalMinor());
    }

    private function order(OrderStatus $status): Order
    {
        return new Order(
            id: 1001,
            merchantId: 'mer_17',
            customerId: 'cus_3',
            status: $status,
            lines: [new OrderLine('MUG-01', 'Enamel mug', 2, 1250), new OrderLine('TEE-M', 'T-shirt, M', 1, 899)],
            currency: 'EUR',
            placedAt: new DateTimeImmutable('2026-03-02T10:00:00Z'),
        );
    }
}
