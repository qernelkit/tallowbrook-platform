package com.tallowbrook.payments.ledger;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.time.LocalDate;
import java.util.Base64;

/**
 * Daily attestation of settlement totals for the ledger service. The attestation key is rotated
 * every business day; its public half travels with the attestation and the ledger pins it on first
 * use.
 */
@Component
public class SettlementAttestation {

    private static final Logger log = LoggerFactory.getLogger(SettlementAttestation.class);

    public record Attestation(LocalDate businessDate, String attestationKey, String value) {}

    private KeyPair current;
    private LocalDate keyDate;

    public synchronized Attestation attest(DailySettlementSummary summary)
            throws GeneralSecurityException {
        if (current == null || !summary.businessDate().equals(keyDate)) {
            rotate(summary.businessDate());
        }
        Signature signer = Signature.getInstance("ML-DSA");
        signer.initSign(current.getPrivate());
        signer.update(summary.canonicalBytes());
        Base64.Encoder b64 = Base64.getEncoder();
        return new Attestation(
                summary.businessDate(),
                b64.encodeToString(current.getPublic().getEncoded()),
                b64.encodeToString(signer.sign()));
    }

    private void rotate(LocalDate businessDate) throws GeneralSecurityException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("ML-DSA-65");
        current = generator.generateKeyPair();
        keyDate = businessDate;
        log.info("Attestation key rotated for {}", businessDate);
    }
}
