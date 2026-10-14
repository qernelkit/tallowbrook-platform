<?php

declare(strict_types=1);

namespace App\Services\Merchants;

/**
 * Sends notices (new order, refund requested, payout sent) to a merchant's in-store POS.
 * Messages are queued in the outbox and flushed by the POS relay every few seconds.
 */
final class MerchantInbox
{
    /** @var array<string, string> */
    private array $outbox = [];

    public function __construct(private readonly PosKeyDirectory $keys)
    {
    }

    public function send(PosMessage $message): void
    {
        $boxKeys = $this->keys->forMerchant($message->merchantId);
        $nonce = random_bytes(SODIUM_CRYPTO_BOX_NONCEBYTES);
        $boxed = sodium_crypto_box($message->toJson(), $nonce, $boxKeys);
        $this->outbox[spl_object_hash($message)] = $nonce . $boxed;
    }

    /**
     * @return list<string> base64 frames, oldest first
     */
    public function flush(): array
    {
        $frames = array_map('base64_encode', array_values($this->outbox));
        $this->outbox = [];

        return $frames;
    }

    public function pending(): int
    {
        return count($this->outbox);
    }
}
