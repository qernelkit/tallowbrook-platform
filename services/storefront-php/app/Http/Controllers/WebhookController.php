<?php

declare(strict_types=1);

namespace App\Http\Controllers;

use App\Services\Partners\MarketplaceWebhook;
use App\Services\Partners\PartnerWebhookVerifier;
use App\Services\Partners\WebhookRejected;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

final class WebhookController
{
    public function __construct(
        private readonly MarketplaceWebhook $marketplace,
        private readonly PartnerWebhookVerifier $partners,
    ) {
    }

    public function marketplace(Request $request): JsonResponse
    {
        try {
            $event = $this->marketplace->verify($request, time());
        } catch (WebhookRejected $e) {
            return new JsonResponse(['error' => $e->getMessage()], 400);
        }

        return new JsonResponse(['received' => $event['type']], 202);
    }

    public function partner(Request $request, string $partnerId): JsonResponse
    {
        $header = $this->partners->headerFor($partnerId);
        if ($header === null) {
            return new JsonResponse(['error' => 'Unknown partner'], 404);
        }
        if (!$this->partners->verify($partnerId, $request->getContent(), (string) $request->header($header, ''))) {
            return new JsonResponse(['error' => 'Rejected'], 400);
        }

        return new JsonResponse(['received' => true], 202);
    }
}
