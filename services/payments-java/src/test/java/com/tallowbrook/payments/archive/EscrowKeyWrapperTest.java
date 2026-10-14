package com.tallowbrook.payments.archive;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.MLKEMKeyPairGenerator;
import org.bouncycastle.crypto.kems.MLKEMExtractor;
import org.bouncycastle.crypto.params.MLKEMKeyGenerationParameters;
import org.bouncycastle.crypto.params.MLKEMParameters;
import org.bouncycastle.crypto.params.MLKEMPrivateKeyParameters;
import org.junit.jupiter.api.Test;

import java.security.SecureRandom;

class EscrowKeyWrapperTest {

    @Test
    void escrowOfficersRecoverTheArchiveKey() {
        SecureRandom random = new SecureRandom();
        MLKEMKeyPairGenerator generator = new MLKEMKeyPairGenerator();
        generator.init(new MLKEMKeyGenerationParameters(random, MLKEMParameters.ml_kem_768));
        AsymmetricCipherKeyPair escrow = generator.generateKeyPair();

        EscrowedArchiveKey archiveKey =
                new EscrowKeyWrapper(escrow.getPublic(), random).newArchiveKey();

        MLKEMExtractor officers =
                new MLKEMExtractor((MLKEMPrivateKeyParameters) escrow.getPrivate());
        assertArrayEquals(archiveKey.secret(), officers.extractSecret(archiveKey.encapsulation()));
        assertEquals(32, archiveKey.secret().length);
    }
}
