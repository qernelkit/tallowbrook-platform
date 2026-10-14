<?php

declare(strict_types=1);

namespace App\Services\Pos;

/**
 * Outbound sync frames (price changes, stock levels) for in-store POS terminals.
 *
 * Each terminal registered its public key when it was linked; the storefront's own key pair
 * is in POS_SYNC_KEYS. Session keys are derived per frame from the pair.
 */
final class PosSyncChannel
{
    public function __construct(private readonly string $storefrontKx)
    {
    }

    /**
     * @param array<string, mixed> $payload
     */
    public function frame(string $terminalId, string $terminalKey, array $payload): string
    {
        $json = json_encode(['terminal' => $terminalId, 'sent_at' => time(), 'payload' => $payload], JSON_THROW_ON_ERROR);

        [, $tx] = sodium_crypto_kx_client_session_keys($this->storefrontKx, $terminalKey);
        $txKey = hash_hkdf('sha256', $tx, 32, 'pos-sync/v2');
        $nonce = random_bytes(SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES);
        $frame = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt($json, $terminalId, $nonce, $txKey);

        return base64_encode($nonce . $frame);
    }

    /**
     * @param array<string, string> $terminals terminal id => registered key
     * @param array<string, mixed> $payload
     * @return array<string, string>
     */
    public function broadcast(array $terminals, array $payload): array
    {
        $frames = [];
        foreach ($terminals as $terminalId => $terminalKey) {
            $frames[$terminalId] = $this->frame($terminalId, $terminalKey, $payload);
        }

        return $frames;
    }
}
