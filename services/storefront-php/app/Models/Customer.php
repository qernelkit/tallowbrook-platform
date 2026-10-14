<?php

declare(strict_types=1);

namespace App\Models;

final class Customer
{
    public function __construct(
        public readonly string $id,
        public readonly string $email,
        public readonly string $name,
        public readonly string $locale = 'en',
        public bool $marketingOptIn = false,
    ) {
    }

    public function firstName(): string
    {
        $parts = explode(' ', trim($this->name), 2);

        return $parts[0];
    }
}
