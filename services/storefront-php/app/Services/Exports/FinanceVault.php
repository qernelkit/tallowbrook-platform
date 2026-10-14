<?php

declare(strict_types=1);

namespace App\Services\Exports;

/**
 * The finance team's key vault (an internal service). Write-only from the storefront.
 */
interface FinanceVault
{
    public function store(string $quarter, string $pem): void;
}
