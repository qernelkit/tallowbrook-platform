<?php

declare(strict_types=1);

namespace App\Services\Reports;

use Defuse\Crypto\Crypto;
use Defuse\Crypto\Key;

/**
 * Monthly merchant reports. Our copy is archived under the archive key; a merchant can ask for
 * a copy protected with a password of their own instead, for their accountant.
 */
final class ReportArchive
{
    public function __construct(private readonly Key $archiveKey)
    {
    }

    public static function fromEnvironment(): self
    {
        return new self(Key::loadFromAsciiSafeString((string) getenv('REPORT_ARCHIVE_KEY')));
    }

    public function archiveCopy(string $reportCsv): string
    {
        $sealed = Crypto::encrypt($reportCsv, $this->archiveKey);

        return $sealed;
    }

    public function merchantCopy(string $reportCsv, string $merchantPassword): string
    {
        $sealed = Crypto::encryptWithPassword($reportCsv, $merchantPassword);

        return $sealed;
    }

    public function fileName(string $merchantId, string $month): string
    {
        return sprintf('%s-report-%s.bin', $merchantId, $month);
    }
}
