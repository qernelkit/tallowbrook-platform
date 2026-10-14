<?php

declare(strict_types=1);

namespace App\Services\Imports;

use RuntimeException;

/**
 * Reads order exports produced by the v1 storefront, for merchants moving their history over.
 *
 * A v1 export is one JSON header line ({"salt": "...", "iv": "...", "rows": 1234}, base64 values)
 * followed by the CSV body, protected with a key derived from the merchant's export password.
 */
final class V1OrderImporter
{
    private const V1_CIPHER = 'aes-128-cbc';
    private const COLUMNS = ['order_no', 'placed_at', 'customer_email', 'sku', 'qty', 'unit_price', 'currency'];

    /**
     * @return list<array<string, string>>
     */
    public function import(string $file, string $password): array
    {
        [$headerLine, $body] = array_pad(explode("\n", $file, 2), 2, '');
        $header = json_decode($headerLine, true, 4);
        if (!is_array($header) || !isset($header['salt'], $header['iv'], $header['rows'])) {
            throw new RuntimeException('Not a v1 order export');
        }

        $salt = base64_decode((string) $header['salt'], true);
        $iv = base64_decode((string) $header['iv'], true);
        if ($salt === false || $iv === false) {
            throw new RuntimeException('v1 export header is damaged');
        }

        $key = openssl_pbkdf2($password, $salt, 16, 1000);
        $csv = openssl_decrypt((string) base64_decode(trim($body)), self::V1_CIPHER, (string) $key, OPENSSL_RAW_DATA, $iv);
        if ($csv === false) {
            throw new RuntimeException('Wrong export password, or the file is damaged');
        }

        $rows = $this->parse($csv);
        if (count($rows) !== (int) $header['rows']) {
            throw new RuntimeException(sprintf('Expected %d rows, found %d', (int) $header['rows'], count($rows)));
        }

        return $rows;
    }

    /**
     * @return list<array<string, string>>
     */
    private function parse(string $csv): array
    {
        $rows = [];
        $lines = preg_split('/\r?\n/', trim($csv)) ?: [];
        array_shift($lines);
        foreach ($lines as $number => $line) {
            $fields = str_getcsv($line, ',', '"', '');
            if (count($fields) !== count(self::COLUMNS)) {
                throw new RuntimeException(sprintf('Line %d has %d fields', $number + 2, count($fields)));
            }
            $rows[] = array_combine(self::COLUMNS, array_map('strval', $fields));
        }

        return $rows;
    }
}
