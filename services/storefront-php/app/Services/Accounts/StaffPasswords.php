<?php

declare(strict_types=1);

namespace App\Services\Accounts;

use InvalidArgumentException;

/**
 * Passwords of merchant staff accounts (the people who use the merchant dashboard).
 */
final class StaffPasswords
{
    public const MIN_LENGTH = 12;

    public function __construct(private readonly BreachedPasswordCheck $breaches)
    {
    }

    public function hash(string $password): string
    {
        if (mb_strlen($password) < self::MIN_LENGTH) {
            throw new InvalidArgumentException('Passwords need at least 12 characters');
        }
        if ($this->breaches->isBreached($password)) {
            throw new InvalidArgumentException('This password appears in a known data breach; choose another');
        }

        return password_hash($password, PASSWORD_ARGON2ID, ['memory_cost' => 65536, 'time_cost' => 4, 'threads' => 1]);
    }

    public function check(string $password, string $stored): bool
    {
        return password_verify($password, $stored);
    }
}
