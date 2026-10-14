<?php

declare(strict_types=1);

namespace App\Http\Requests;

/**
 * Validates the key file a merchant uploads in the dashboard before it is stored. The file is
 * only checked for shape here; the partner team reviews it before it is activated.
 */
final class MerchantPublicKeyUpload
{
    private const PEM_PATTERN = '/^-----BEGIN PUBLIC KEY-----\R/';
    private const MAX_BYTES = 16384;
    private const ALLOWED_EXTENSIONS = ['pem', 'pub', 'txt'];

    /**
     * @return list<string>
     */
    public static function errors(string $fileName, string $contents): array
    {
        $errors = [];
        $extension = strtolower(pathinfo($fileName, PATHINFO_EXTENSION));
        if (!in_array($extension, self::ALLOWED_EXTENSIONS, true)) {
            $errors[] = 'Upload a .pem, .pub or .txt file.';
        }
        if (strlen($contents) === 0) {
            $errors[] = 'The file is empty.';
        } elseif (strlen($contents) > self::MAX_BYTES) {
            $errors[] = 'The file is larger than 16 KB.';
        }
        if (preg_match(self::PEM_PATTERN, ltrim($contents)) !== 1) {
            $errors[] = 'The file must be in PEM format, as exported by your platform.';
        }
        if (!mb_check_encoding($contents, 'ASCII')) {
            $errors[] = 'The file contains characters that are not plain text.';
        }

        return $errors;
    }
}
