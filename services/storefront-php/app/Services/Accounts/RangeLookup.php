<?php

declare(strict_types=1);

namespace App\Services\Accounts;

/**
 * Client for the breach corpus range API: given a 5-character prefix it returns
 * "SUFFIX:COUNT" lines for every known entry with that prefix.
 */
interface RangeLookup
{
    public function range(string $prefix): string;
}
