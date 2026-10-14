package com.tallowbrook.payments.card;

import org.springframework.stereotype.Component;

import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

/**
 * Hands a batch data key to an acquirer that needs to read card data from a chargeback export: the
 * key is wrapped to the acquirer's RSA key from their onboarding pack.
 */
@Component
public class DataKeyTransport {

    public String wrapForAcquirer(SecretKey dataKey, PublicKey acquirerKey)
            throws GeneralSecurityException {
        Cipher transport = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        transport.init(Cipher.WRAP_MODE, acquirerKey);
        return Base64.getEncoder().encodeToString(transport.wrap(dataKey));
    }
}
