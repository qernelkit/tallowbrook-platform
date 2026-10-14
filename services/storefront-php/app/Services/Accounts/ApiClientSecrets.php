<?php

declare(strict_types=1);

namespace App\Services\Accounts;

/**
 * Client secrets for merchants' API clients. The plain secret is shown once; we keep the hash.
 */
final class ApiClientSecrets
{
    public function generate(): string
    {
        return 'tbsk_' . bin2hex(random_bytes(24));
    }

    public function hashForStorage(string $secret): string
    {
        return password_hash($secret, PASSWORD_BCRYPT, ['cost' => 12]);
    }

    public function matches(string $secret, string $stored): bool
    {
        return str_starts_with($secret, 'tbsk_') && password_verify($secret, $stored);
    }
}
