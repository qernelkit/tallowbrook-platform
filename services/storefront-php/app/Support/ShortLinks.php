<?php

declare(strict_types=1);

namespace App\Support;

use Hashids\Hashids;

/**
 * Short public links for order status pages: https://tbk.example/o/{code}.
 */
final class ShortLinks
{
    private readonly Hashids $hashids;

    public function __construct(?string $shortLinkSalt = null, private readonly string $baseUrl = 'https://tbk.example/o/')
    {
        $shortLinkSalt ??= (string) Config::get('services.hashids.salt', '');
        $this->hashids = new Hashids($shortLinkSalt, 8);
    }

    public function forOrder(int $orderId): string
    {
        return $this->baseUrl . $this->hashids->encode($orderId);
    }

    public function orderId(string $code): ?int
    {
        $ids = $this->hashids->decode($code);

        return isset($ids[0]) ? (int) $ids[0] : null;
    }
}
