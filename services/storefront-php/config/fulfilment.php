<?php

declare(strict_types=1);

return [
    'warehouse_sftp' => [
        'host' => env('WAREHOUSE_SFTP_HOST', 'sftp.northgate-wms.example'),
        'port' => 22,
        'username' => env('WAREHOUSE_SFTP_USER', 'tallowbrook'),
        'key_path' => env('WAREHOUSE_SFTP_KEY', 'storage/keys/warehouse-sftp'),
        'remote_dir' => '/inbound/picklists',
        'timeout' => 20,
        'kex' => [
            'curve25519-sha256',
            'ecdh-sha2-nistp256',
            'diffie-hellman-group14-sha256',
        ],
    ],
    'pick_list' => [
        'cutoff' => '14:30',
        'max_lines' => 500,
    ],
];
