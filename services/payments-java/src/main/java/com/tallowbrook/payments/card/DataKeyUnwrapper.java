package com.tallowbrook.payments.card;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

/** Unwraps the per-batch data keys stored next to each batch of vault rows. */
@Component
public class DataKeyUnwrapper {

    private static final Logger log = LoggerFactory.getLogger(DataKeyUnwrapper.class);

    private final CardVaultKeys keys;

    public DataKeyUnwrapper(CardVaultKeys keys) {
        this.keys = keys;
    }

    public SecretKey unwrap(String keyId, byte[] wrappedKey) throws GeneralSecurityException {
        try {
            Cipher unwrapper = Cipher.getInstance("AESWrap");
            return unwrapWith(unwrapper, wrappedKey);
        } catch (InvalidKeyException e) {
            log.warn("AESWrap integrity check failed for data key {}", keyId);
            throw new DataKeyException(keyId, e);
        }
    }

    private SecretKey unwrapWith(Cipher unwrapper, byte[] wrappedKey)
            throws GeneralSecurityException {
        unwrapper.init(Cipher.UNWRAP_MODE, keys.vaultKek());
        return (SecretKey) unwrapper.unwrap(wrappedKey, "AES", Cipher.SECRET_KEY);
    }

    public static class DataKeyException extends GeneralSecurityException {

        public DataKeyException(String keyId, Throwable cause) {
            super("Data key " + keyId + " could not be unwrapped", cause);
        }
    }
}
