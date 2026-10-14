package com.tallowbrook.payments.archive;

import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.NamedParameterSpec;

/**
 * Prepares the next escrow key pair during the yearly escrow ceremony. The private half goes to the
 * ceremony tooling, which splits it between the officers; the public half is published for the
 * service configuration.
 */
@Component
public class EscrowKeyRotation {

    public KeyPair nextEscrowKeys() throws GeneralSecurityException {
        KeyPairGenerator next = KeyPairGenerator.getInstance("ML-KEM");
        next.initialize(NamedParameterSpec.ML_KEM_1024);
        return next.generateKeyPair();
    }

    public Path publish(KeyPair keys, Path outDir, int year) throws IOException {
        Files.createDirectories(outDir);
        Path out = outDir.resolve("escrow-" + year + ".spki.der");
        Files.write(out, keys.getPublic().getEncoded());
        return out;
    }
}
