package com.tallowbrook.payments.acquirer;

import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;

/**
 * LotusPay, the wallet acquirer for our APAC merchants. Their gateway requires every request body
 * to be signed with the merchant-of-record key registered in their console, in the form their
 * regulator mandates.
 */
@Component
public class LotusPayAdapter {

    public KeyPair registrationKeys() throws GeneralSecurityException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC", "BC");
        generator.initialize(new ECGenParameterSpec("sm2p256v1"));
        return generator.generateKeyPair();
    }

    /** Value of the {@code X-Lotus-Signature} header. */
    public String signRequest(PrivateKey registeredKey, String requestBody)
            throws GeneralSecurityException {
        Signature signer = Signature.getInstance("SM3withSM2", "BC");
        signer.initSign(registeredKey);
        signer.update(requestBody.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(signer.sign());
    }
}
