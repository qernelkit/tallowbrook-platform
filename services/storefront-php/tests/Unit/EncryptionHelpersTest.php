<?php

declare(strict_types=1);

namespace Tests\Unit;

use App\Support\EncryptionHelpers;
use PHPUnit\Framework\TestCase;

final class EncryptionHelpersTest extends TestCase
{
    public function testMasksNames(): void
    {
        self::assertSame('J*** S****', EncryptionHelpers::encrypt_name('Jane Smith'));
        self::assertSame('Ö****', EncryptionHelpers::encrypt_name('  Örjan '));
    }

    public function testMasksEmails(): void
    {
        self::assertSame('j*********@example.com', EncryptionHelpers::mask_email('jane.smith@example.com'));
        self::assertSame('*****', EncryptionHelpers::mask_email('nope!'));
    }

    public function testMasksPhones(): void
    {
        self::assertSame('********789', EncryptionHelpers::mask_phone('+44 1234 56789'));
    }
}
