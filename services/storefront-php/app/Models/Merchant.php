<?php

declare(strict_types=1);

namespace App\Models;

final class Merchant
{
    public function __construct(
        public readonly string $id,
        public readonly string $name,
        public readonly string $contactEmail,
        public readonly string $country,
        public int $exportKeyVersion = 2,
        public string $exportKeySalt = '',
        public ?string $apiKeyId = null,
        public bool $active = true,
    ) {
    }

    public function displayName(): string
    {
        return $this->active ? $this->name : $this->name . ' (inactive)';
    }
}
