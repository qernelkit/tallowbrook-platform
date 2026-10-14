package com.tallowbrook.payments.card;

import org.springframework.stereotype.Component;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

/**
 * Card data at rest. A stored value is {@code iv || ciphertext || tag}; the token is bound in as
 * associated data so a row cannot be swapped under another token.
 */
@Component
public class CardDataCipher {

    public static final String TRANSFORMATION = "AES/GCM/NoPadding";
    static final int TAG_BITS = 128;
    static final int IV_BYTES = 12;

    private final SecureRandom random;

    public CardDataCipher(SecureRandom paymentsRandom) {
        this.random = paymentsRandom;
    }

    public byte[] seal(SecretKey dataKey, byte[] cardData, byte[] associatedData)
            throws GeneralSecurityException {
        byte[] iv = new byte[IV_BYTES];
        random.nextBytes(iv);
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, dataKey, parameters(iv));
        cipher.updateAAD(associatedData);
        byte[] sealed = cipher.doFinal(cardData);
        return ByteBuffer.allocate(IV_BYTES + sealed.length).put(iv).put(sealed).array();
    }

    public byte[] open(SecretKey dataKey, byte[] stored, byte[] associatedData)
            throws GeneralSecurityException {
        if (stored.length <= IV_BYTES) {
            throw new IllegalArgumentException("Stored value too short");
        }
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, dataKey, parameters(Arrays.copyOf(stored, IV_BYTES)));
        cipher.updateAAD(associatedData);
        return cipher.doFinal(stored, IV_BYTES, stored.length - IV_BYTES);
    }

    static GCMParameterSpec parameters(byte[] iv) {
        return new GCMParameterSpec(TAG_BITS, iv);
    }
}
