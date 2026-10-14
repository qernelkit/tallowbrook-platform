<?php

declare(strict_types=1);

namespace App\Services\Couriers;

use RuntimeException;

/**
 * Seals the daily pickup manifest for the courier partner. Their depot software opens it with
 * the private half of the key they gave us at onboarding.
 */
final class CourierManifestSealer
{
    public function __construct(private readonly string $courierKeyPath)
    {
    }

    /**
     * @return array{sealed: string, wrapped_key: string, iv: string}
     */
    public function seal(string $manifestJson): array
    {
        $courierKey = openssl_pkey_get_public('file://' . $this->courierKeyPath);
        if ($courierKey === false) {
            throw new RuntimeException("Courier key at {$this->courierKeyPath} is unreadable");
        }

        $iv = random_bytes(16);
        $sealed = '';
        $envelopeKeys = [];
        $ok = openssl_seal($manifestJson, $sealed, $envelopeKeys, [$courierKey], 'aes-256-cbc', $iv);
        if ($ok === false || !isset($envelopeKeys[0])) {
            throw new RuntimeException('Sealing the courier manifest failed');
        }

        return [
            'sealed' => base64_encode($sealed),
            'wrapped_key' => base64_encode($envelopeKeys[0]),
            'iv' => base64_encode($iv),
        ];
    }
}
