package com.tallowbrook.payments.partner;

import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.NamedParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import javax.crypto.KDF;
import javax.crypto.KEM;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.HKDFParameterSpec;

/**
 * Key exchange for the partner file channel. We offer two public keys per exchange; the partner
 * answers with an encapsulation to the first and its own key for the second, and both sides feed
 * the two shared secrets into one channel key.
 */
@Component
public class PartnerKemChannel {

    private static final Duration OFFER_TTL = Duration.ofMinutes(10);
    private static final byte[] CHANNEL_CONTEXT =
            "tallowbrook-partner-channel/v1".getBytes(StandardCharsets.US_ASCII);

    public record Offer(String exchangeId, byte[] encapsulationKey, byte[] agreementKey) {}

    private record Pending(PrivateKey decapsulationKey, PrivateKey agreementKey, Instant created) {}

    private final Map<String, Pending> pending = new ConcurrentHashMap<>();

    public Offer offer(String partnerId) throws GeneralSecurityException {
        KeyPair kemKeys = KeyPairGenerator.getInstance("ML-KEM-768").generateKeyPair();
        KeyPairGenerator xdh = KeyPairGenerator.getInstance("XDH");
        xdh.initialize(NamedParameterSpec.X25519);
        KeyPair agreementKeys = xdh.generateKeyPair();
        String exchangeId = partnerId + ":" + Instant.now().toEpochMilli();
        pending.put(
                exchangeId,
                new Pending(kemKeys.getPrivate(), agreementKeys.getPrivate(), Instant.now()));
        return new Offer(
                exchangeId,
                kemKeys.getPublic().getEncoded(),
                agreementKeys.getPublic().getEncoded());
    }

    public SecretKey complete(String exchangeId, byte[] encapsulation, byte[] partnerAgreementKey)
            throws GeneralSecurityException {
        Pending exchange = pending.remove(exchangeId);
        if (exchange == null || exchange.created().plus(OFFER_TTL).isBefore(Instant.now())) {
            throw new IllegalStateException("Unknown or expired exchange " + exchangeId);
        }
        KEM kem = KEM.getInstance("ML-KEM");
        SecretKey kemSecret =
                kem.newDecapsulator(exchange.decapsulationKey()).decapsulate(encapsulation);
        PublicKey partnerKey =
                KeyFactory.getInstance("XDH")
                        .generatePublic(new X509EncodedKeySpec(partnerAgreementKey));
        KeyAgreement agreement = KeyAgreement.getInstance("X25519");
        agreement.init(exchange.agreementKey());
        agreement.doPhase(partnerKey, true);
        byte[] agreed = agreement.generateSecret();
        KDF combiner = KDF.getInstance("HKDF-SHA256");
        return combiner.deriveKey(
                "AES",
                HKDFParameterSpec.ofExtract()
                        .addIKM(kemSecret.getEncoded())
                        .addIKM(agreed)
                        .thenExpand(CHANNEL_CONTEXT, 32));
    }

    public void expireOffers() {
        Instant cutoff = Instant.now().minus(OFFER_TTL);
        pending.entrySet().removeIf(e -> e.getValue().created().isBefore(cutoff));
    }
}
