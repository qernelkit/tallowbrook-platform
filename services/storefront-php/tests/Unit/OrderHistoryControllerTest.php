<?php

declare(strict_types=1);

namespace Tests\Unit;

use App\Enums\OrderStatus;
use App\Http\Controllers\OrderHistoryController;
use App\Models\Customer;
use App\Models\Order;
use App\Services\Orders\OrderRepository;
use App\Support\OrderIdObfuscator;
use DateTimeImmutable;
use Illuminate\Http\Request;
use PHPUnit\Framework\TestCase;

final class OrderHistoryControllerTest extends TestCase
{
    public function testOtherCustomersOrdersAreNotFound(): void
    {
        $references = new OrderIdObfuscator(bin2hex(random_bytes(8)));
        $orders = $this->createStub(OrderRepository::class);
        $orders->method('find')->willReturn($this->order('cus_other'));

        $controller = new OrderHistoryController($orders, $references);
        $response = $controller->show($references->encode(5), new Customer('cus_me', 'me@example.com', 'Me'));

        self::assertSame(404, $response->getStatusCode());
    }

    public function testIndexListsOrders(): void
    {
        $orders = $this->createStub(OrderRepository::class);
        $orders->method('forCustomer')->willReturn([$this->order('cus_me')]);

        $controller = new OrderHistoryController($orders, new OrderIdObfuscator(bin2hex(random_bytes(8))));
        $response = $controller->index(Request::create('/orders', 'GET', ['page' => '1']), new Customer('cus_me', 'me@example.com', 'Me'));
        $body = json_decode((string) $response->getContent(), true);

        self::assertIsArray($body);
        self::assertCount(1, $body['orders']);
        self::assertSame('shipped', $body['orders'][0]['status']);
    }

    private function order(string $customerId): Order
    {
        return new Order(5, 'mer_1', $customerId, OrderStatus::Shipped, [], 'EUR', new DateTimeImmutable('2026-01-10'));
    }
}
