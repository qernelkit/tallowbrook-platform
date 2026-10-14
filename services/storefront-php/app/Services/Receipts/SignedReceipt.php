<?php

declare(strict_types=1);

namespace App\Services\Receipts;

final class SignedReceipt
{
    public function __construct(
        public readonly string $receiptNo,
        public readonly string $body,
        public readonly string $signature,
    ) {
    }
}
