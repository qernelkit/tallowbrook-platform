<?php

declare(strict_types=1);

namespace App\Services\Lockers;

use App\Models\Locker;

interface LockerRepository
{
    public function find(string $lockerId): ?Locker;

    public function storeLinkSecret(string $lockerId, string $secret): void;

    public function markOnline(string $lockerId, string $firmware): void;
}
