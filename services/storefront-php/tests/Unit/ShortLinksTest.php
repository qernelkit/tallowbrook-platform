<?php

declare(strict_types=1);

namespace Tests\Unit;

use App\Support\ShortLinks;
use PHPUnit\Framework\TestCase;

final class ShortLinksTest extends TestCase
{
    public function testLinksDecodeBackToTheOrder(): void
    {
        $links = new ShortLinks(bin2hex(random_bytes(4)), 'https://tbk.example/o/');
        $url = $links->forOrder(31337);

        self::assertStringStartsWith('https://tbk.example/o/', $url);
        self::assertSame(31337, $links->orderId(substr($url, strlen('https://tbk.example/o/'))));
    }

    public function testUnknownCodeGivesNull(): void
    {
        $links = new ShortLinks(bin2hex(random_bytes(4)));

        self::assertNull($links->orderId('!!!'));
    }
}
