<?php

declare(strict_types=1);

namespace App\Http\Controllers;

use App\Models\GiftCard;
use App\Services\GiftCards\GiftCardPins;
use DateTimeImmutable;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

final class GiftCardController
{
    /**
     * @param \Closure(string): ?GiftCard $findCard
     */
    public function __construct(
        private readonly \Closure $findCard,
        private readonly GiftCardPins $pins,
    ) {
    }

    public function balance(Request $request): JsonResponse
    {
        $code = strtoupper(str_replace(['-', ' '], '', (string) $request->input('code')));
        $card = ($this->findCard)($code);
        if ($card === null) {
            return new JsonResponse(['error' => 'We do not know this card'], 404);
        }
        if (!$this->pins->check($card, (string) $request->input('pin', ''))) {
            return new JsonResponse(['error' => 'Wrong PIN'], 403);
        }

        return new JsonResponse([
            'balance_minor' => $card->balanceMinor,
            'currency' => $card->currency,
            'expired' => $card->isExpired(new DateTimeImmutable()),
            'expires_at' => $card->expiresAt->format('Y-m-d'),
        ]);
    }

    public function setPin(Request $request): JsonResponse
    {
        $card = ($this->findCard)((string) $request->input('code'));
        if ($card === null) {
            return new JsonResponse(['error' => 'We do not know this card'], 404);
        }
        if ($card->pinHash !== null) {
            return new JsonResponse(['error' => 'This card already has a PIN'], 409);
        }
        $card->pinHash = $this->pins->hash((string) $request->input('pin'));

        return new JsonResponse(['status' => 'ok']);
    }
}
