package com.tallowbrook.payments.settlement;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.jcajce.JcaPGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Date;
import java.util.Iterator;

/**
 * The acquiring bank receives settlement files as ASCII-armoured OpenPGP messages, encrypted to the
 * key from their onboarding pack.
 */
@Component
public class SettlementPgpEncryptor {

    private static final int BUFFER = 1 << 16;

    private final SecureRandom random;

    public SettlementPgpEncryptor(SecureRandom paymentsRandom) {
        this.random = paymentsRandom;
    }

    public void protect(Path settlementFile, Path bankKeyFile, Path target)
            throws IOException, PGPException {
        PGPPublicKey bankKey = readBankKey(bankKeyFile);
        PGPCompressedDataGenerator compressed =
                new PGPCompressedDataGenerator(CompressionAlgorithmTags.ZIP);
        PGPEncryptedDataGenerator encryptedData =
                new PGPEncryptedDataGenerator(
                        new JcePGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256)
                                .setWithIntegrityPacket(true)
                                .setSecureRandom(random));
        encryptedData.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(bankKey));

        try (OutputStream file = Files.newOutputStream(target);
                ArmoredOutputStream armored = new ArmoredOutputStream(file);
                OutputStream sealed = encryptedData.open(armored, new byte[BUFFER]);
                OutputStream packed = compressed.open(sealed);
                InputStream in = Files.newInputStream(settlementFile)) {
            PGPLiteralDataGenerator literal = new PGPLiteralDataGenerator();
            try (OutputStream body =
                    literal.open(
                            packed,
                            PGPLiteralData.BINARY,
                            settlementFile.getFileName().toString(),
                            Files.size(settlementFile),
                            new Date())) {
                in.transferTo(body);
            }
        }
    }

    private static PGPPublicKey readBankKey(Path bankKeyFile) throws IOException, PGPException {
        try (InputStream in = PGPUtil.getDecoderStream(Files.newInputStream(bankKeyFile))) {
            JcaPGPPublicKeyRingCollection rings = new JcaPGPPublicKeyRingCollection(in);
            for (PGPPublicKeyRing ring : rings) {
                Iterator<PGPPublicKey> keys = ring.getPublicKeys();
                while (keys.hasNext()) {
                    PGPPublicKey candidate = keys.next();
                    if (candidate.isEncryptionKey() && !candidate.hasRevocation()) {
                        return candidate;
                    }
                }
            }
        }
        throw new IllegalStateException("No usable encryption key in " + bankKeyFile);
    }
}
