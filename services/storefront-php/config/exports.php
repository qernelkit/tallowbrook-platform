<?php

declare(strict_types=1);

return [
    'disk' => 'settlements',
    'delimiter' => ',',
    'signature_algo' => OPENSSL_ALGO_SHA256,
    'key_path' => env('EXPORT_KEY_PATH', 'storage/keys/settlement-exports.pem'),
    'retention_days' => 400,
];
