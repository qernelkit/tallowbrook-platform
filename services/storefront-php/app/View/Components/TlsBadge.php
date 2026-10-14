<?php

declare(strict_types=1);

namespace App\View\Components;

/**
 * The padlock badge shown under the "Pay now" button.
 */
final class TlsBadge
{
    public string $cipherSuiteLabel = 'Secure checkout';

    public function __construct(
        public readonly string $merchantName,
        public readonly bool $compact = false,
    ) {
    }

    public function render(): string
    {
        $label = htmlspecialchars($this->cipherSuiteLabel, ENT_QUOTES);
        $merchant = htmlspecialchars($this->merchantName, ENT_QUOTES);

        if ($this->compact) {
            return sprintf('<span class="checkout-badge checkout-badge--compact">%s</span>', $label);
        }

        return sprintf(
            '<div class="checkout-badge"><span class="checkout-badge__icon" aria-hidden="true"></span>'
            . '<span>%s</span><small>Payments for %s are handled by Tallowbrook.</small></div>',
            $label,
            $merchant,
        );
    }
}
