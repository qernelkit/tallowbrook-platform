<?php

declare(strict_types=1);

namespace App\Support;

use Illuminate\Encryption\Encrypter;
use RuntimeException;

/**
 * Builds the application encrypter from config/app.php. It protects cookies, queued job
 * payloads and the "remember this card" tokens.
 */
final class AppEncrypter
{
    private static ?Encrypter $instance = null;

    public static function instance(): Encrypter
    {
        return self::$instance ??= self::make(Config::section('app'));
    }

    /**
     * @param array<string, mixed> $app
     */
    public static function make(array $app): Encrypter
    {
        $key = (string) ($app['key'] ?? '');
        if (str_starts_with($key, 'base64:')) {
            $key = (string) base64_decode(substr($key, 7), true);
        }
        if ($key === '') {
            throw new RuntimeException('APP_KEY is not set; copy .env.example and set it');
        }

        return new Encrypter($key, $app['cipher']);
    }
}
