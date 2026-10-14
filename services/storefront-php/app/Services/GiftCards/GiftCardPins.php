<?php

declare(strict_types=1);

namespace App\Services\GiftCards;

use App\Models\GiftCard;
use InvalidArgumentException;

/**
 * Optional PINs customers can put on a gift card before giving it away.
 */
final class GiftCardPins
{
    public function hash(string $pin): string
    {
        if (!preg_match('/^\d{4,8}$/', $pin)) {
            throw new InvalidArgumentException('A PIN is 4 to 8 digits');
        }

        return password_hash($pin, PASSWORD_DEFAULT);
    }

    public function check(GiftCard $card, string $pin): bool
    {
        return $card->pinHash === null || password_verify($pin, $card->pinHash);
    }
}
