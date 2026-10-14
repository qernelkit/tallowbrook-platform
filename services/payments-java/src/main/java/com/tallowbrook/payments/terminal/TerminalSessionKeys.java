package com.tallowbrook.payments.terminal;

import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;

import javax.crypto.KDF;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.HKDFParameterSpec;

/**
 * Session keys for the depot terminal link: both ends contribute an ephemeral key pair, and the
 * agreed secret is expanded with the reader's serial number as context.
 */
@Component
public class TerminalSessionKeys {

    private static final String SESSION_KDF = "HKDF-SHA256";
    private static final int SESSION_KEY_BYTES = 32;

    public KeyPair newEphemeral() throws GeneralSecurityException {
        KeyPairGenerator ephemeral = KeyPairGenerator.getInstance("EC");
        ephemeral.initialize(new ECGenParameterSpec("secp256r1"));
        return ephemeral.generateKeyPair();
    }

    public SecretKey sessionKey(
            PrivateKey ours, PublicKey readerKey, byte[] readerSalt, String readerSerial)
            throws GeneralSecurityException {
        KeyAgreement agreement = KeyAgreement.getInstance("ECDH");
        agreement.init(ours);
        agreement.doPhase(readerKey, true);
        byte[] shared = agreement.generateSecret();
        KDF kdf = KDF.getInstance(SESSION_KDF);
        byte[] context = ("tallowbrook-terminal/" + readerSerial).getBytes(StandardCharsets.UTF_8);
        return kdf.deriveKey(
                "AES",
                HKDFParameterSpec.ofExtract()
                        .addIKM(shared)
                        .addSalt(readerSalt)
                        .thenExpand(context, SESSION_KEY_BYTES));
    }
}
