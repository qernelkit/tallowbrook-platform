<?php

declare(strict_types=1);

namespace App\Support;

use InvalidArgumentException;

/**
 * Reads values from config/*.php with a dotted path: Config::get('exports.disk').
 *
 * Each config file returns an array and is loaded once per process.
 */
final class Config
{
    /** @var array<string, array<string, mixed>> */
    private static array $files = [];

    private static ?string $directory = null;

    public static function useDirectory(string $directory): void
    {
        self::$directory = rtrim($directory, '/');
        self::$files = [];
    }

    public static function get(string $path, mixed $default = null): mixed
    {
        $segments = explode('.', $path);
        $file = array_shift($segments);
        if ($file === '') {
            throw new InvalidArgumentException('Config path must start with a file name');
        }

        $value = self::load($file);
        foreach ($segments as $segment) {
            if (!is_array($value) || !array_key_exists($segment, $value)) {
                return $default;
            }
            $value = $value[$segment];
        }

        return $value;
    }

    /**
     * @return array<string, mixed>
     */
    public static function section(string $path): array
    {
        $value = self::get($path, []);

        return is_array($value) ? $value : [];
    }

    /**
     * @return array<string, mixed>
     */
    private static function load(string $file): array
    {
        if (!array_key_exists($file, self::$files)) {
            $path = (self::$directory ?? dirname(__DIR__, 2) . '/config') . '/' . $file . '.php';
            $loaded = is_file($path) ? require $path : [];
            self::$files[$file] = is_array($loaded) ? $loaded : [];
        }

        return self::$files[$file];
    }
}
