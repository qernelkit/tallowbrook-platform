<?php

declare(strict_types=1);

namespace App\Services\Merchants;

use App\Models\Merchant;
use RuntimeException;

/**
 * Derives the key a merchant's settlement exports are protected with, from the export password
 * the merchant sets in the dashboard.
 *
 * Version 2 uses a per-merchant salt. Merchants who set their password before March 2025 are
 * still on version 1 until they change it; the dashboard nudges them on every login.
 */
final class MerchantExportKeys
{
    private const EXPORT_KEY_SALT = "\x13\x4b\x77\x95\xcd\x0a\x7a\xb2\x11\xc4\xf2\x2c\x15\x1d\x24\xe0";

    public function derive(Merchant $merchant, string $password): string
    {
        if ($password === '') {
            throw new RuntimeException('Export password is empty');
        }

        return match ($merchant->exportKeyVersion) {
            2 => $this->deriveV2($password, $merchant->exportKeySalt),
            1 => $this->deriveV1($password),
            default => throw new RuntimeException("Unknown export key version {$merchant->exportKeyVersion}"),
        };
    }

    public function upgrade(Merchant $merchant, string $password): string
    {
        $merchant->exportKeySalt = random_bytes(SODIUM_CRYPTO_PWHASH_SALTBYTES);
        $merchant->exportKeyVersion = 2;

        return $this->derive($merchant, $password);
    }

    private function deriveV2(string $password, string $salt): string
    {
        return sodium_crypto_pwhash(
            32,
            $password,
            $salt,
            SODIUM_CRYPTO_PWHASH_OPSLIMIT_MODERATE,
            SODIUM_CRYPTO_PWHASH_MEMLIMIT_MODERATE,
            SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13
        );
    }

    private function deriveV1(string $password): string
    {
        $key = openssl_pbkdf2($password, self::EXPORT_KEY_SALT, 32, 600_000, 'sha256');
        if ($key === false) {
            throw new RuntimeException('Export key derivation failed');
        }

        return $key;
    }
}
