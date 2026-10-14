<?php

declare(strict_types=1);

namespace App\Support;

/**
 * Helpers for writing customer details to logs and support tickets without exposing them.
 */
final class EncryptionHelpers
{
    /**
     * "Jane Smith" becomes "J*** S****".
     */
    public static function encrypt_name(string $name): string
    {
        $parts = preg_split('/\s+/', trim($name)) ?: [];

        return implode(' ', array_map(
            static fn (string $part): string => mb_substr($part, 0, 1) . str_repeat('*', max(mb_strlen($part) - 1, 0)),
            $parts,
        ));
    }

    /**
     * "jane.smith@example.com" becomes "j*********@example.com".
     */
    public static function mask_email(string $email): string
    {
        $at = strrpos($email, '@');
        if ($at === false || $at === 0) {
            return str_repeat('*', strlen($email));
        }

        return $email[0] . str_repeat('*', $at - 1) . substr($email, $at);
    }

    /**
     * Keeps the last three digits of a phone number.
     */
    public static function mask_phone(string $phone): string
    {
        $digits = preg_replace('/\D+/', '', $phone) ?? '';

        return str_repeat('*', max(strlen($digits) - 3, 0)) . substr($digits, -3);
    }
}
