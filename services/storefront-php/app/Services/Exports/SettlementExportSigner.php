<?php

declare(strict_types=1);

namespace App\Services\Exports;

use App\Support\Config;
use RuntimeException;

/**
 * Signs the settlement CSV that merchants download, so their accounting tools can check the
 * file came from Tallowbrook. The signature is written next to the CSV as {name}.sig.
 */
final class SettlementExportSigner
{
    public function __construct(private readonly string $keyPath)
    {
    }

    public static function fromConfig(): self
    {
        return new self((string) Config::get('exports.key_path'));
    }

    public function sign(string $csv): string
    {
        $merchantKey = openssl_pkey_get_private('file://' . $this->keyPath);
        if ($merchantKey === false) {
            throw new RuntimeException("Cannot read the export key at {$this->keyPath}");
        }

        $signature = '';
        if (!openssl_sign($csv, $signature, $merchantKey, Config::get('exports.signature_algo'))) {
            throw new RuntimeException('Signing the settlement export failed');
        }

        return base64_encode($signature);
    }

    public function sidecarName(string $csvName): string
    {
        return preg_replace('/\.csv$/i', '', $csvName) . '.sig';
    }
}
