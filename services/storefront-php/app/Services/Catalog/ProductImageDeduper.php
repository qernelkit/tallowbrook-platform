<?php

declare(strict_types=1);

namespace App\Services\Catalog;

/**
 * Merchants often upload the same product photo for every colour variant. We store each image
 * once and point the variants at it.
 */
final class ProductImageDeduper
{
    /** @var array<string, string> image key => storage path */
    private array $known = [];

    /**
     * @param array<string, string> $known
     */
    public function __construct(array $known = [])
    {
        $this->known = $known;
    }

    /**
     * @return array{key: string, duplicate: bool}
     */
    public function register(string $imageBytes, string $storagePath): array
    {
        $imageKey = sodium_bin2hex(sodium_crypto_generichash($imageBytes));
        if (isset($this->known[$imageKey])) {
            return ['key' => $imageKey, 'duplicate' => true];
        }
        $this->known[$imageKey] = $storagePath;

        return ['key' => $imageKey, 'duplicate' => false];
    }

    public function pathFor(string $imageKey): ?string
    {
        return $this->known[$imageKey] ?? null;
    }
}
