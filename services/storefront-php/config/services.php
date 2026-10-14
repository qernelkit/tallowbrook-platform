<?php

declare(strict_types=1);

return [
    // Customer session tokens, read by the tracking pages and the courier app.
    'session_tokens' => [
        'alg' => 'RS256',
        'kid' => env('SESSION_TOKEN_KID', 'sf-2026-03'),
        'issuer' => 'https://shop.tallowbrook.example',
        'ttl' => 900,
        'key_path' => env('SESSION_TOKEN_KEY_PATH', 'storage/keys/session-tokens.pem'),
    ],

    'marketplace' => [
        'webhook_secret' => env('MARKETPLACE_WEBHOOK_SECRET'),
        'tolerance_seconds' => 300,
    ],

    'partners' => [
        'bearer_secret' => env('PARTNER_BEARER_SECRET'),
    ],

    'preview_links' => [
        'secret' => env('PREVIEW_LINK_SECRET'),
        'ttl_minutes' => 60,
    ],

    'order_refs' => [
        'mask' => env('ORDER_REF_MASK', ''),
    ],

    'hashids' => [
        'salt' => env('HASHIDS_SALT', ''),
        'min_length' => 8,
    ],
];
