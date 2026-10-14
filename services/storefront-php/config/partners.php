<?php

declare(strict_types=1);

// Payment partners. Harbor Pay posts settlement webhooks signed with its own RSA key;
// Quayside does not send webhooks and is polled by the settlement job instead.
return [
    'harbor-pay' => [
        'name' => 'Harbor Pay',
        'endpoint' => 'https://api.harborpay.example/v2',
        'webhooks' => true,
        'verify_key_path' => env('HARBOR_PAY_VERIFY_KEY', 'storage/keys/harbor-pay.pem'),
        'webhook_algo' => OPENSSL_ALGO_SHA1,
        'signature_header' => 'X-Harbor-Signature',
    ],
    'quayside' => [
        'name' => 'Quayside Payments',
        'endpoint' => 'https://merchants.quayside.example/api',
        'webhooks' => false,
        'poll_minutes' => 15,
    ],
];
