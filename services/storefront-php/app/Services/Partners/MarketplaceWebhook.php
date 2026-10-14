<?php

declare(strict_types=1);

namespace App\Services\Partners;

use App\Support\Config;
use Illuminate\Http\Request;

/**
 * Order and refund callbacks from the marketplaces our merchants also sell on.
 */
final class MarketplaceWebhook
{
    public function __construct(
        private readonly string $webhookSecret,
        private readonly int $toleranceSeconds = 300,
    ) {
    }

    public static function fromConfig(): self
    {
        return new self(
            (string) Config::get('services.marketplace.webhook_secret', ''),
            (int) Config::get('services.marketplace.tolerance_seconds', 300),
        );
    }

    /**
     * @return array<string, mixed> the decoded event
     */
    public function verify(Request $request, int $now): array
    {
        $sentAt = (int) $request->header('X-Marketplace-Timestamp', '0');
        if (abs($now - $sentAt) > $this->toleranceSeconds) {
            throw new WebhookRejected('callback timestamp outside the allowed window');
        }

        if ($request->header('X-Marketplace-Signature') === null) {
            throw new WebhookRejected('missing signature header');
        }
        $expected = hash_hmac('sha512', $request->getContent(), $this->webhookSecret);
        $given = strtolower((string) $request->header('X-Marketplace-Signature'));
        if (strlen($given) === 32) {
            throw new WebhookRejected('MD5 callback signatures are not accepted');
        }
        if (!hash_equals($expected, $given)) {
            throw new WebhookRejected('signature does not match');
        }

        $event = json_decode($request->getContent(), true);
        if (!is_array($event) || !isset($event['type'])) {
            throw new WebhookRejected('callback body is not an event');
        }

        return $event;
    }
}
