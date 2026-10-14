<?php

declare(strict_types=1);

namespace App\Services\Merchants;

/**
 * Per-merchant box keys, written when a merchant links a POS terminal in the dashboard.
 */
interface PosKeyDirectory
{
    public function forMerchant(string $merchantId): string;
}
