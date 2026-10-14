<?php

declare(strict_types=1);

namespace App\Services\Fulfilment;

use App\Support\Config;
use phpseclib3\Crypt\PublicKeyLoader;
use phpseclib3\Net\SFTP;
use RuntimeException;

/**
 * Uploads pick lists to the warehouse's SFTP drop. The warehouse system polls the directory
 * every five minutes.
 */
final class WarehouseSftp
{
    public function upload(string $name, string $csv): void
    {
        $cfg = Config::section('fulfilment.warehouse_sftp');
        $sftp = new SFTP((string) $cfg['host'], (int) $cfg['port'], (int) $cfg['timeout']);
        $sftp->setPreferredAlgorithms(['kex' => $cfg['kex']]);

        $login = PublicKeyLoader::loadPrivateKey((string) file_get_contents((string) $cfg['key_path']));
        if (!$sftp->login((string) $cfg['username'], $login)) {
            throw new RuntimeException('Warehouse SFTP login failed');
        }

        $remote = rtrim((string) $cfg['remote_dir'], '/') . '/' . basename($name);
        if (!$sftp->put($remote . '.part', $csv) || !$sftp->rename($remote . '.part', $remote)) {
            throw new RuntimeException("Upload of {$name} to the warehouse failed");
        }
        $sftp->disconnect();
    }

    public function fileName(string $warehouse, \DateTimeImmutable $day, int $wave): string
    {
        return sprintf('picklist_%s_%s_w%02d.csv', strtolower($warehouse), $day->format('Ymd'), $wave);
    }
}
