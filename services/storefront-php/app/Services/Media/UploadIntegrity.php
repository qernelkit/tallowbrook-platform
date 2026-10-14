<?php

declare(strict_types=1);

namespace App\Services\Media;

use App\Enums\UploadChecksum;

/**
 * Checks product media uploads against the checksum the merchant's upload tool sends in
 * X-Upload-Checksum (value) and X-Upload-Checksum-Algorithm (which one).
 */
final class UploadIntegrity
{
    public const MAX_UPLOAD_BYTES = 25 * 1024 * 1024;

    public function verify(string $bytes, UploadChecksum $algorithm, string $expected): bool
    {
        if (strlen($bytes) > self::MAX_UPLOAD_BYTES) {
            return false;
        }
        $actual = hash($algorithm->value, $bytes);

        return hash_equals($actual, strtolower(trim($expected)));
    }

    /**
     * @param array<string, string|null> $headers
     */
    public function verifyFromHeaders(string $bytes, array $headers): bool
    {
        $algorithm = UploadChecksum::fromHeader($headers['x-upload-checksum-algorithm'] ?? null);
        $expected = $headers['x-upload-checksum'] ?? null;
        if ($algorithm === null || $expected === null) {
            return false;
        }

        return $this->verify($bytes, $algorithm, $expected);
    }
}
