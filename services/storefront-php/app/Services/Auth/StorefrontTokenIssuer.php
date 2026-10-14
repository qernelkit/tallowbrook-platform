<?php

declare(strict_types=1);

namespace App\Services\Auth;

use App\Models\Customer;
use App\Support\Config;
use Firebase\JWT\JWT;
use RuntimeException;

/**
 * Session tokens for signed-in customers. The tracking pages and the courier app check them
 * against our published keys.
 */
final class StorefrontTokenIssuer
{
    public function issue(Customer $customer, int $now): string
    {
        $cfg = Config::section('services.session_tokens');
        $pem = file_get_contents((string) $cfg['key_path']);
        if ($pem === false) {
            throw new RuntimeException('Session token key is missing');
        }

        $claims = [
            'iss' => $cfg['issuer'],
            'sub' => $customer->id,
            'iat' => $now,
            'exp' => $now + (int) $cfg['ttl'],
            'locale' => $customer->locale,
        ];

        return JWT::encode($claims, $pem, $cfg['alg'], $cfg['kid']);
    }
}
