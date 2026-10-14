<?php

declare(strict_types=1);

namespace App\Http\Controllers;

use App\Models\Customer;
use App\Models\Order;
use App\Services\Orders\OrderRepository;
use App\Support\OrderIdObfuscator;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use InvalidArgumentException;

final class OrderHistoryController
{
    private const PAGE_SIZE = 20;

    public function __construct(
        private readonly OrderRepository $orders,
        private readonly OrderIdObfuscator $references,
    ) {
    }

    public function index(Request $request, Customer $customer): JsonResponse
    {
        $page = max(1, (int) $request->query('page', '1'));
        $orders = $this->orders->forCustomer($customer->id, self::PAGE_SIZE, ($page - 1) * self::PAGE_SIZE);

        return new JsonResponse([
            'page' => $page,
            'orders' => array_map(fn (Order $order): array => $this->summary($order), $orders),
        ]);
    }

    public function show(string $reference, Customer $customer): JsonResponse
    {
        try {
            $order = $this->orders->find($this->references->decode($reference));
        } catch (InvalidArgumentException) {
            $order = null;
        }
        if ($order === null || $order->customerId !== $customer->id) {
            return new JsonResponse(['error' => 'Order not found'], 404);
        }

        return new JsonResponse($this->summary($order) + [
            'lines' => array_map(static fn ($line): array => [
                'sku' => $line->sku,
                'title' => $line->title,
                'qty' => $line->quantity,
            ], $order->lines),
        ]);
    }

    public function cancel(string $reference, Customer $customer): JsonResponse
    {
        $order = $this->orders->find($this->references->decode($reference));
        if ($order === null || $order->customerId !== $customer->id) {
            return new JsonResponse(['error' => 'Order not found'], 404);
        }
        if (!$order->canBeCancelled()) {
            return new JsonResponse(['error' => 'This order has already been packed'], 409);
        }
        $this->orders->cancel($order->id);

        return new JsonResponse(['status' => 'cancelled']);
    }

    /**
     * @return array<string, mixed>
     */
    private function summary(Order $order): array
    {
        return [
            'reference' => $this->references->encode($order->id),
            'status' => $order->status->value,
            'status_label' => $order->status->label(),
            'placed_at' => $order->placedAt->format(DATE_ATOM),
            'items' => $order->itemCount(),
            'total_minor' => $order->totalMinor(),
            'currency' => $order->currency,
            'tracking_number' => $order->trackingNumber,
        ];
    }
}
