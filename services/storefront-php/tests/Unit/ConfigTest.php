<?php

declare(strict_types=1);

namespace Tests\Unit;

use App\Support\Config;
use PHPUnit\Framework\TestCase;

final class ConfigTest extends TestCase
{
    private string $dir;

    protected function setUp(): void
    {
        $this->dir = sys_get_temp_dir() . '/storefront-config-' . bin2hex(random_bytes(4));
        mkdir($this->dir);
        file_put_contents($this->dir . '/shop.php', "<?php return ['name' => 'Corner Shop', 'hours' => ['mon' => '9-17']];");
        Config::useDirectory($this->dir);
    }

    protected function tearDown(): void
    {
        unlink($this->dir . '/shop.php');
        rmdir($this->dir);
    }

    public function testReadsNestedValues(): void
    {
        self::assertSame('Corner Shop', Config::get('shop.name'));
        self::assertSame('9-17', Config::get('shop.hours.mon'));
    }

    public function testFallsBackToDefault(): void
    {
        self::assertSame('closed', Config::get('shop.hours.sun', 'closed'));
        self::assertNull(Config::get('missing.anything'));
    }

    public function testSectionIsAlwaysAnArray(): void
    {
        self::assertSame(['mon' => '9-17'], Config::section('shop.hours'));
        self::assertSame([], Config::section('shop.name'));
    }
}
