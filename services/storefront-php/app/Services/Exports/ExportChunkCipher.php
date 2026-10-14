<?php

declare(strict_types=1);

namespace App\Services\Exports;

use phpseclib3\Crypt\AES;
use RuntimeException;

/**
 * Settlement exports for large merchants run to several hundred MB, so they are processed in
 * 1 MB chunks with a continuous counter instead of being loaded into memory.
 */
final class ExportChunkCipher
{
    private const CHUNK_BYTES = 1048576;

    private AES $ctr;

    public function __construct(string $dataKey, string $iv)
    {
        $this->ctr = new AES('ctr');
        $this->ctr->setKeyLength(256);
        $this->ctr->setKey($dataKey);
        $this->ctr->setIV($iv);
        $this->ctr->enableContinuousBuffer();
    }

    /**
     * @param resource $in
     * @param resource $out
     */
    public function process($in, $out): int
    {
        $total = 0;
        while (!feof($in)) {
            $chunk = fread($in, self::CHUNK_BYTES);
            if ($chunk === false) {
                throw new RuntimeException('Reading the export failed');
            }
            if ($chunk === '') {
                continue;
            }
            if (fwrite($out, $this->ctr->encrypt($chunk)) === false) {
                throw new RuntimeException('Writing the export failed');
            }
            $total += strlen($chunk);
        }

        return $total;
    }
}
