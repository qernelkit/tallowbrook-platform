<?php

declare(strict_types=1);

namespace App\Services\Merchants;

final class PosMessage
{
    /**
     * @param array<string, scalar|null> $data
     */
    public function __construct(
        public readonly string $merchantId,
        public readonly string $type,
        public readonly array $data,
    ) {
    }

    public function toJson(): string
    {
        return json_encode(['type' => $this->type, 'data' => $this->data], JSON_THROW_ON_ERROR);
    }
}
