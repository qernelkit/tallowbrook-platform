<?php

declare(strict_types=1);

namespace App\Services\Lockers;

use App\Models\Locker;
use RuntimeException;

/**
 * Enrols a smart pickup locker with the storefront.
 *
 * The locker sends its public key (PEM) in the enrolment request; we answer with ours, and both
 * sides end up with the same 32-byte link secret, which the locker uses to authenticate its
 * door-open reports.
 */
final class LockerEnrolment
{
    public function __construct(private readonly LockerRepository $lockers)
    {
    }

    public function enrol(Locker $locker, string $lockerPem, string $firmware): string
    {
        $ours = openssl_pkey_new([
            'private_key_type' => OPENSSL_KEYTYPE_EC,
            'curve_name' => 'prime256v1',
        ]);
        $lockerPublic = openssl_pkey_get_public($lockerPem);
        if ($ours === false || $lockerPublic === false) {
            throw new RuntimeException("Locker {$locker->id} sent a key we cannot read");
        }

        $shared = openssl_pkey_derive($lockerPublic, $ours, 32);
        if ($shared === false) {
            throw new RuntimeException("Enrolment of locker {$locker->id} failed");
        }
        $this->lockers->storeLinkSecret($locker->id, $shared);
        $this->lockers->markOnline($locker->id, $firmware);

        $details = openssl_pkey_get_details($ours);

        return $details === false ? '' : (string) $details['key'];
    }
}
