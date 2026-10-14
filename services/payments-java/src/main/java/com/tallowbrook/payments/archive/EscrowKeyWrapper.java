package com.tallowbrook.payments.archive;

import com.tallowbrook.payments.config.PaymentsProperties;

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.kems.MLKEMGenerator;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.openssl.PEMParser;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.Reader;
import java.nio.file.Files;
import java.security.SecureRandom;

/**
 * Every archive gets its own key, encapsulated to the long-term escrow key held by the escrow
 * officers.
 */
@Component
public class EscrowKeyWrapper {

    private final AsymmetricKeyParameter escrowKey;
    private final SecureRandom random;

    @Autowired
    public EscrowKeyWrapper(PaymentsProperties properties, SecureRandom paymentsRandom)
            throws IOException {
        this(readEscrowKey(properties), paymentsRandom);
    }

    EscrowKeyWrapper(AsymmetricKeyParameter escrowKey, SecureRandom random) {
        this.escrowKey = escrowKey;
        this.random = random;
    }

    public EscrowedArchiveKey newArchiveKey() {
        MLKEMGenerator encapsulator = new MLKEMGenerator(random);
        SecretWithEncapsulation result = encapsulator.generateEncapsulated(escrowKey);
        return new EscrowedArchiveKey(result.getSecret(), result.getEncapsulation());
    }

    private static AsymmetricKeyParameter readEscrowKey(PaymentsProperties properties)
            throws IOException {
        try (Reader reader = Files.newBufferedReader(properties.archive().escrowPublicKey());
                PEMParser parser = new PEMParser(reader)) {
            Object parsed = parser.readObject();
            if (!(parsed instanceof SubjectPublicKeyInfo info)) {
                throw new IllegalStateException("Escrow key file does not hold a public key");
            }
            return PublicKeyFactory.createKey(info);
        }
    }
}
