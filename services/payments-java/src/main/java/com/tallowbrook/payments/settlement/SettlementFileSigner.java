package com.tallowbrook.payments.settlement;

import com.tallowbrook.payments.hsm.HsmAlgorithms;
import com.tallowbrook.payments.hsm.KeyCeremonyRunner;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Signature;
import java.util.Base64;

/** Signs outgoing settlement files with the settlement key held on the payments token. */
@Service
public class SettlementFileSigner {

    private static final Logger log = LoggerFactory.getLogger(SettlementFileSigner.class);
    private static final int CHUNK = 64 * 1024;

    private final Provider hsm;
    private final KeyStore token;

    public SettlementFileSigner(@Qualifier("paymentsHsm") Provider hsm)
            throws GeneralSecurityException, IOException {
        this.hsm = hsm;
        this.token = KeyStore.getInstance("PKCS11", hsm);
        token.load(null, null);
    }

    /**
     * Returns the detached signature, base64, for the {@code .sig} file sent next to the settlement
     * file.
     */
    public String sign(Path settlementFile) throws GeneralSecurityException, IOException {
        PrivateKey key = (PrivateKey) token.getKey(KeyCeremonyRunner.SETTLEMENT_KEY_LABEL, null);
        if (key == null) {
            throw new IllegalStateException(
                    "Settlement key not found on the token; run the key ceremony first");
        }
        Signature signer = Signature.getInstance(HsmAlgorithms.SETTLEMENT_SIGNATURE, hsm);
        signer.initSign(key);
        byte[] buffer = new byte[CHUNK];
        long total = 0;
        try (InputStream in = Files.newInputStream(settlementFile)) {
            int read;
            while ((read = in.read(buffer)) > 0) {
                signer.update(buffer, 0, read);
                total += read;
            }
        }
        log.info("Signed {} ({} bytes)", settlementFile.getFileName(), total);
        return Base64.getEncoder().encodeToString(signer.sign());
    }
}
