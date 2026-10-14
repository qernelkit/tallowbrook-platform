<?php

declare(strict_types=1);

namespace App\Services\Receipts;

final class Receipt
{
    /**
     * @param list<array{sku: string, qty: int, price_minor: int}> $lines
     */
    public function __construct(
        public readonly int $terminalId,
        public readonly int $sequence,
        public readonly string $merchantId,
        public readonly array $lines,
        public readonly string $currency,
        public readonly string $issuedAt,
    ) {
    }

    public function canonicalJson(): string
    {
        $data = [
            'currency' => $this->currency,
            'issued_at' => $this->issuedAt,
            'lines' => $this->lines,
            'merchant' => $this->merchantId,
            'sequence' => $this->sequence,
            'terminal' => $this->terminalId,
        ];

        return json_encode($data, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    }
}
