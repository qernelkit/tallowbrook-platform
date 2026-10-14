<?php

declare(strict_types=1);

namespace App\Services\Exports;

use phpseclib3\Crypt\RSA;
use phpseclib3\Crypt\RSA\PrivateKey;

/**
 * Each quarter the finance team gets a fresh wrapping key. The private half goes straight to
 * their vault; the storefront keeps only the wrapped data keys of the exports it writes, so
 * finance can open any export of that quarter without the storefront being able to.
 */
final class ExportKeyWrapper
{
    private PrivateKey $wrappingKey;

    public function __construct(private readonly FinanceVault $vault, private readonly string $quarter)
    {
        $this->wrappingKey = RSA::createKey(3072)
            ->withPadding(RSA::ENCRYPTION_OAEP)
            ->withHash('sha256')
            ->withMGFHash('sha256');
    }

    public function handOver(): void
    {
        $this->vault->store($this->quarter, $this->wrappingKey->toString('PKCS8'));
    }

    public function wrap(string $dataKey): string
    {
        return base64_encode($this->wrappingKey->getPublicKey()->encrypt($dataKey));
    }
}
