package com.tallowbrook.payments.merchant;

import com.tallowbrook.payments.card.CardDataCipher;

import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Merchants protect their transaction exports with a passphrase they choose in the portal. Exports
 * use the same sealed format as card data, keyed by the passphrase.
 */
@Component
public class MerchantExportKeys {

    private static final byte[] EXPORT_KEY_SALT =
            "tallowbrook/merchant-export/v2".getBytes(StandardCharsets.UTF_8);
    private static final byte[] EXPORT_HEADER = "TBX2".getBytes(StandardCharsets.US_ASCII);

    private final CardDataCipher sealer;

    public MerchantExportKeys(CardDataCipher sealer) {
        this.sealer = sealer;
    }

    public byte[] protect(char[] passphrase, String merchantId, byte[] exportCsv)
            throws GeneralSecurityException {
        byte[] sealed =
                sealer.seal(
                        exportKey(passphrase),
                        exportCsv,
                        merchantId.getBytes(StandardCharsets.UTF_8));
        byte[] out = new byte[EXPORT_HEADER.length + sealed.length];
        System.arraycopy(EXPORT_HEADER, 0, out, 0, EXPORT_HEADER.length);
        System.arraycopy(sealed, 0, out, EXPORT_HEADER.length, sealed.length);
        return out;
    }

    SecretKey exportKey(char[] passphrase) throws GeneralSecurityException {
        if (passphrase.length < 10) {
            throw new IllegalArgumentException("Export passphrases are at least 10 characters");
        }
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        PBEKeySpec spec = new PBEKeySpec(passphrase, EXPORT_KEY_SALT, 210_000, 256);
        try {
            return new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
        } finally {
            spec.clearPassword();
        }
    }
}
