package com.tallowbrook.payments.terminal;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.pqc.crypto.lms.LMOtsParameters;
import org.bouncycastle.pqc.crypto.lms.LMSKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.lms.LMSKeyPairGenerator;
import org.bouncycastle.pqc.crypto.lms.LMSParameters;
import org.bouncycastle.pqc.crypto.lms.LMSPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.lms.LMSSigner;
import org.bouncycastle.pqc.crypto.lms.LMSigParameters;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.SecureRandom;

/**
 * Signs configuration bundles pushed to the depot card readers. The reader firmware verifies
 * stateful hash-based signatures, so the signing state is written back to disk after every bundle;
 * a crash between signing and saving must never reuse a leaf.
 */
@Component
public class TerminalConfigSigner {

    private static final Logger log = LoggerFactory.getLogger(TerminalConfigSigner.class);

    private final SecureRandom random;

    public TerminalConfigSigner(SecureRandom paymentsRandom) {
        this.random = paymentsRandom;
    }

    public AsymmetricCipherKeyPair newSigningKey() {
        LMSKeyPairGenerator generator = new LMSKeyPairGenerator();
        generator.init(
                new LMSKeyGenerationParameters(
                        new LMSParameters(
                                LMSigParameters.lms_sha256_n32_h10, LMOtsParameters.sha256_n32_w4),
                        random));
        return generator.generateKeyPair();
    }

    public synchronized byte[] sign(Path stateFile, byte[] bundle) throws IOException {
        LMSPrivateKeyParameters key =
                LMSPrivateKeyParameters.getInstance(Files.readAllBytes(stateFile));
        if (key.getUsagesRemaining() == 0) {
            throw new IllegalStateException("Reader configuration key is exhausted; rotate it");
        }
        LMSSigner signer = new LMSSigner();
        signer.init(true, key);
        byte[] signature = signer.generateSignature(bundle);
        Path next = stateFile.resolveSibling(stateFile.getFileName() + ".next");
        Files.write(next, key.getEncoded());
        Files.move(
                next,
                stateFile,
                StandardCopyOption.ATOMIC_MOVE,
                StandardCopyOption.REPLACE_EXISTING);
        log.info("Signed reader bundle; {} signatures left on this key", key.getUsagesRemaining());
        return signature;
    }
}
