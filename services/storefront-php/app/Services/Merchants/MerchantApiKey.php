<?php

declare(strict_types=1);

namespace App\Services\Merchants;

/**
 * Returned once, at provisioning: the merchant downloads the private half and we keep the public half.
 */
final class MerchantApiKey
{
    public function __construct(
        public readonly string $merchantId,
        public readonly string $keyId,
        public readonly string $publicPem,
        public readonly string $privatePem,
    ) {
    }
}
