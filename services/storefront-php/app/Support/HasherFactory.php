<?php

declare(strict_types=1);

namespace App\Support;

use Illuminate\Hashing\BcryptHasher;

/**
 * Builds the password hasher for storefront customer accounts from config/hashing.php.
 */
final class HasherFactory
{
    public static function make(): BcryptHasher
    {
        $hashing = Config::section('hashing');

        return new BcryptHasher($hashing['bcrypt']);
    }
}
