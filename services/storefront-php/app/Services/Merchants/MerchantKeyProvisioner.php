<?php

declare(strict_types=1);

namespace App\Services\Merchants;

use App\Models\Merchant;
use RuntimeException;

/**
 * Creates the key pair a merchant's backend uses to sign calls to the storefront API.
 */
final class MerchantKeyProvisioner
{
    public function provision(Merchant $merchant): MerchantApiKey
    {
        $key = openssl_pkey_new([
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
            'private_key_bits' => 2048,
        ]);
        if ($key === false) {
            throw new RuntimeException('Could not create the merchant API key');
        }

        $privatePem = '';
        openssl_pkey_export($key, $privatePem);
        $details = openssl_pkey_get_details($key);
        if ($details === false) {
            throw new RuntimeException('Could not read the new merchant API key');
        }

        $keyId = sprintf('%s-%s', $merchant->id, date('Ymd'));
        $merchant->apiKeyId = $keyId;

        return new MerchantApiKey($merchant->id, $keyId, (string) $details['key'], $privatePem);
    }
}
