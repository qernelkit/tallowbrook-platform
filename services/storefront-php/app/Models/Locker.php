<?php

declare(strict_types=1);

namespace App\Models;

final class Locker
{
    public function __construct(
        public readonly string $id,
        public readonly string $siteName,
        public readonly string $postcode,
        public readonly int $compartments,
        public bool $online = false,
        public ?string $firmware = null,
    ) {
    }

    public function label(): string
    {
        return sprintf('%s (%s), %d compartments', $this->siteName, $this->postcode, $this->compartments);
    }
}
