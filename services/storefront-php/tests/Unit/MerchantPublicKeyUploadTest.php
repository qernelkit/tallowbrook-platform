<?php

declare(strict_types=1);

namespace Tests\Unit;

use App\Http\Requests\MerchantPublicKeyUpload;
use PHPUnit\Framework\TestCase;

final class MerchantPublicKeyUploadTest extends TestCase
{
    public function testRejectsWrongExtension(): void
    {
        $errors = MerchantPublicKeyUpload::errors('key.docx', 'hello');

        self::assertContains('Upload a .pem, .pub or .txt file.', $errors);
    }

    public function testRejectsEmptyFile(): void
    {
        self::assertContains('The file is empty.', MerchantPublicKeyUpload::errors('key.pem', ''));
    }

    public function testRejectsFilesThatAreNotArmoured(): void
    {
        $errors = MerchantPublicKeyUpload::errors('key.txt', "just some text\n");

        self::assertContains('The file must be in PEM format, as exported by your platform.', $errors);
    }
}
