<?php

declare(strict_types=1);

namespace App\Services\GiftCards;

use RuntimeException;

/**
 * Builds the batch file of new gift-card codes that goes to the card printer. The printer's
 * plant opens it with the key it shares with us; nobody in between sees the codes.
 */
final class GiftCardCodes
{
    private const ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';

    public function __construct(private readonly string $printVendorKey)
    {
        if (strlen($printVendorKey) !== 32) {
            throw new RuntimeException('Print vendor key must be 32 bytes');
        }
    }

    /**
     * @return list<string>
     */
    public function generate(int $count): array
    {
        $codes = [];
        while (count($codes) < $count) {
            $code = '';
            for ($i = 0; $i < 16; $i++) {
                $code .= self::ALPHABET[random_int(0, strlen(self::ALPHABET) - 1)];
            }
            $codes[$code] = true;
        }

        return array_map('strval', array_keys($codes));
    }

    /**
     * @param list<string> $codes
     */
    public function batchFile(array $codes, int $valueMinor, string $currency): string
    {
        $batchCsv = "code,value_minor,currency\n";
        foreach ($codes as $code) {
            $batchCsv .= sprintf("%s,%d,%s\n", implode('-', str_split($code, 4)), $valueMinor, $currency);
        }

        $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        $sealed = sodium_crypto_secretbox($batchCsv, $nonce, $this->printVendorKey);

        return base64_encode($nonce . $sealed);
    }
}
