<?php

declare(strict_types=1);

namespace App\Services\Vault;

use JsonException;
use RuntimeException;

/**
 * Seals customer delivery addresses before they are written to the orders database.
 *
 * Stored form: "v{keyVersion}:" . base64(iv . tag . ciphertext). The customer id is bound in as
 * associated data, so a sealed address copied onto another customer's order will not open.
 */
final class AddressVault
{
    private const CIPHER = 'aes-256-gcm';
    private const IV_LENGTH = 12;
    private const TAG_LENGTH = 16;

    public function __construct(
        private readonly string $key,
        private readonly int $keyVersion,
    ) {
        if (strlen($key) !== 32) {
            throw new RuntimeException('The address vault key must be 32 bytes');
        }
    }

    public static function fromEnvironment(): self
    {
        $key = base64_decode((string) getenv('ADDRESS_VAULT_KEY'), true);
        if ($key === false) {
            throw new RuntimeException('ADDRESS_VAULT_KEY is missing or not base64');
        }

        return new self($key, (int) (getenv('ADDRESS_VAULT_KEY_VERSION') ?: 1));
    }

    /**
     * @param array<string, string> $address
     */
    public function seal(array $address, string $customerId): string
    {
        $plain = json_encode($address, JSON_THROW_ON_ERROR);
        $iv = random_bytes(self::IV_LENGTH);
        $tag = '';
        $sealed = openssl_encrypt($plain, self::CIPHER, $this->key, OPENSSL_RAW_DATA, $iv, $tag, $customerId, self::TAG_LENGTH);
        if ($sealed === false) {
            throw new RuntimeException('Could not seal the address');
        }

        return sprintf('v%d:%s', $this->keyVersion, base64_encode($iv . $tag . $sealed));
    }

    /**
     * @return array<string, string>
     */
    public function open(string $stored, string $customerId): array
    {
        if (!preg_match('/^v(\d+):(.+)$/', $stored, $m) || (int) $m[1] !== $this->keyVersion) {
            throw new RuntimeException('Address was sealed with another key version');
        }
        $raw = base64_decode($m[2], true);
        if ($raw === false || strlen($raw) <= self::IV_LENGTH + self::TAG_LENGTH) {
            throw new RuntimeException('Sealed address is truncated');
        }

        $iv = substr($raw, 0, self::IV_LENGTH);
        $tag = substr($raw, self::IV_LENGTH, self::TAG_LENGTH);
        $body = substr($raw, self::IV_LENGTH + self::TAG_LENGTH);
        $plain = openssl_decrypt($body, self::CIPHER, $this->key, OPENSSL_RAW_DATA, $iv, $tag, $customerId);
        if ($plain === false) {
            throw new RuntimeException('Sealed address does not belong to this customer');
        }

        try {
            $address = json_decode($plain, true, 8, JSON_THROW_ON_ERROR);
        } catch (JsonException $e) {
            throw new RuntimeException('Sealed address is not valid JSON', 0, $e);
        }

        return is_array($address) ? array_map('strval', $address) : [];
    }
}
