<?php

declare(strict_types=1);

namespace App\Http\Controllers;

use App\Models\Customer;
use App\Services\Orders\OrderRepository;
use App\Support\Hashing\CartFingerprint;
use App\Support\OrderIdObfuscator;
use App\Support\ShortLinks;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

final class CheckoutController
{
    private const MAX_LINES = 50;

    public function __construct(
        private readonly OrderRepository $orders,
        private readonly OrderIdObfuscator $references,
        private readonly ShortLinks $links,
    ) {
    }

    public function placeOrder(Request $request, Customer $customer): JsonResponse
    {
        $lines = $request->input('lines');
        if (!is_array($lines) || $lines === [] || count($lines) > self::MAX_LINES) {
            return new JsonResponse(['error' => 'A basket holds between 1 and 50 lines'], 422);
        }

        $clean = [];
        foreach ($lines as $line) {
            if (!is_array($line) || !is_string($line['sku'] ?? null) || !is_int($line['qty'] ?? null) || $line['qty'] < 1) {
                return new JsonResponse(['error' => 'Each line needs a sku and a positive qty'], 422);
            }
            $clean[] = ['sku' => $line['sku'], 'qty' => $line['qty']];
        }

        $dedupeKey = CartFingerprint::dedupeKey($clean);
        $existing = $this->orders->findOpenByCartKey($customer->id, $dedupeKey);
        if ($existing !== null) {
            return new JsonResponse([
                'reference' => $this->references->encode($existing),
                'duplicate' => true,
            ], 200);
        }

        $orderId = $this->orders->create($customer->id, (string) $request->input('merchant_id'), $clean, $dedupeKey);

        return new JsonResponse([
            'reference' => $this->references->encode($orderId),
            'status_url' => $this->links->forOrder($orderId),
        ], 201);
    }

    public function experiment(Customer $customer): JsonResponse
    {
        $bucket = CartFingerprint::experimentBucket($customer->id);

        return new JsonResponse(['one_page_checkout' => $bucket < 20]);
    }
}
