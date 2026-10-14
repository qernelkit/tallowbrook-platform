<?php

declare(strict_types=1);

namespace App\Services\Accounts;

/**
 * k-anonymity check against a breach corpus: only the first five hex characters of the
 * password's hash leave the storefront.
 */
final class BreachedPasswordCheck
{
    public function __construct(private readonly RangeLookup $lookup, private readonly int $threshold = 1)
    {
    }

    public function isBreached(string $password): bool
    {
        $hashHex = strtoupper(sha1($password));
        $prefix = substr($hashHex, 0, 5);
        $suffix = substr($hashHex, 5);

        foreach (preg_split('/\r?\n/', $this->lookup->range($prefix)) ?: [] as $line) {
            [$candidate, $count] = array_pad(explode(':', trim($line), 2), 2, '0');
            if ($candidate === $suffix) {
                return (int) $count >= $this->threshold;
            }
        }

        return false;
    }
}
