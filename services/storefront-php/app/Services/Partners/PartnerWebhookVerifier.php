<?php

declare(strict_types=1);

namespace App\Services\Partners;

use App\Support\Config;

/**
 * Checks settlement webhooks from payment partners that sign them with their own key.
 */
final class PartnerWebhookVerifier
{
    public function verify(string $partnerId, string $body, string $signatureHeader): bool
    {
        $partner = Config::section("partners.$partnerId");
        if (($partner['webhooks'] ?? false) !== true) {
            return false;
        }

        $partnerKey = openssl_pkey_get_public('file://' . $partner['verify_key_path']);
        $sig = base64_decode($signatureHeader, true);
        if ($partnerKey === false || $sig === false || $sig === '') {
            return false;
        }

        return openssl_verify($body, $sig, $partnerKey, $partner['webhook_algo']) === 1;
    }

    public function headerFor(string $partnerId): ?string
    {
        $header = Config::get("partners.$partnerId.signature_header");

        return is_string($header) ? $header : null;
    }
}
