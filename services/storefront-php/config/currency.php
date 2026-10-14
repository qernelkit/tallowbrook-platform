<?php

declare(strict_types=1);

return [
    'base' => 'EUR',
    'display' => ['EUR', 'GBP', 'USD', 'SEK', 'PLN', 'CHF'],
    'rates_provider' => 'ECB',
    'refresh_minutes' => 60,
    'rounding' => [
        'SEK' => 1,
        'PLN' => 2,
    ],
];
