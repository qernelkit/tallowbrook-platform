package com.tallowbrook.payments.webhook;

import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Map;

/**
 * Which signature scheme a merchant callback must use, by the type of key the merchant registered.
 */
final class CallbackSignatureAlgorithms {

    private CallbackSignatureAlgorithms() {}

    private static final Map<String, String> BY_KEY_TYPE =
            Map.of(
                    "EC", "SHA256withECDSA",
                    "RSA", "SHA256withRSA",
                    "EdDSA", "Ed25519");
    private static final String REFUSAL = "not accepted; MD5 and SHA-1 signatures are refused";

    static Signature verifierFor(PublicKey key) throws GeneralSecurityException {
        if (!BY_KEY_TYPE.containsKey(key.getAlgorithm())) {
            throw new IllegalArgumentException(
                    "Callback key type " + key.getAlgorithm() + " is " + REFUSAL);
        }
        Signature verifier = Signature.getInstance(BY_KEY_TYPE.get(key.getAlgorithm()));
        verifier.initVerify(key);
        return verifier;
    }
}
