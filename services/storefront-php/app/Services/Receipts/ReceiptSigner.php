<?php

declare(strict_types=1);

namespace App\Services\Receipts;

use RuntimeException;

/**
 * Digital receipts for in-store sales. Customers (and tax auditors) can check a receipt on the
 * public receipt page, which holds our published verification key.
 */
final class ReceiptSigner
{
    public function __construct(private readonly string $receiptKey)
    {
    }

    public static function fromEnvironment(): self
    {
        $key = base64_decode((string) getenv('RECEIPT_KEY'), true);
        if ($key === false || $key === '') {
            throw new RuntimeException('RECEIPT_KEY is not set');
        }

        return new self($key);
    }

    public function sign(Receipt $receipt): SignedReceipt
    {
        $canonicalReceipt = $receipt->canonicalJson();
        $receiptNo = bin2hex(pack('nN', $receipt->terminalId, $receipt->sequence));
        $signature = sodium_crypto_sign_detached($canonicalReceipt, $this->receiptKey);

        return new SignedReceipt($receiptNo, $canonicalReceipt, base64_encode($signature));
    }
}
