<?php

declare(strict_types=1);

namespace App\Http\Controllers;

use App\Services\Lockers\LockerEnrolment;
use App\Services\Lockers\LockerRepository;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

final class LockerController
{
    public function __construct(
        private readonly LockerRepository $lockers,
        private readonly LockerEnrolment $enrolment,
    ) {
    }

    public function enrol(Request $request, string $lockerId): JsonResponse
    {
        $locker = $this->lockers->find($lockerId);
        if ($locker === null) {
            return new JsonResponse(['error' => 'Unknown locker'], 404);
        }
        if ($locker->online) {
            return new JsonResponse(['error' => 'Locker is already enrolled; reset it on site first'], 409);
        }

        $pem = (string) $request->input('key');
        $firmware = (string) $request->input('firmware', 'unknown');
        $ours = $this->enrolment->enrol($locker, $pem, $firmware);

        return new JsonResponse(['locker' => $locker->label(), 'key' => $ours], 201);
    }

    public function status(string $lockerId): JsonResponse
    {
        $locker = $this->lockers->find($lockerId);
        if ($locker === null) {
            return new JsonResponse(['error' => 'Unknown locker'], 404);
        }

        return new JsonResponse([
            'locker' => $locker->label(),
            'online' => $locker->online,
            'firmware' => $locker->firmware,
        ]);
    }
}
