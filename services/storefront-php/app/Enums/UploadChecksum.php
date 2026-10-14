<?php

declare(strict_types=1);

namespace App\Enums;

/**
 * Checksums a merchant's upload tool may send with product media.
 */
enum UploadChecksum: string
{
    case Sha256 = 'sha256';
    case Sha512 = 'sha512';

    public static function fromHeader(?string $value): ?self
    {
        return $value === null ? null : self::tryFrom(strtolower(trim($value)));
    }
}
