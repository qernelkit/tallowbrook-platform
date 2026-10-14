package com.tallowbrook.payments.webhook;

import com.tallowbrook.payments.config.PaymentsProperties;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Checks inbound partner webhooks. The delivery partner signs the raw body with its RSA key; the
 * smaller partners send an HMAC over {@code timestamp.body} with a shared secret per partner.
 */
@Component
public class PartnerWebhookVerifier {

    static final String SIGNATURE_SCHEME = "RSASSA-PSS";
    static final PSSParameterSpec PSS_PARAMS =
            new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1);

    private final PaymentsProperties properties;
    private final PublicKey partnerKey;

    @Autowired
    public PartnerWebhookVerifier(PaymentsProperties properties) throws GeneralSecurityException {
        this(properties, PartnerKeys.partnerWebhookKey());
    }

    PartnerWebhookVerifier(PaymentsProperties properties, PublicKey partnerKey) {
        this.properties = properties;
        this.partnerKey = partnerKey;
    }

    public boolean verifySignature(byte[] body, String signatureHeader)
            throws GeneralSecurityException {
        if (signatureHeader == null || signatureHeader.isBlank()) {
            return false;
        }
        Signature verifier = Signature.getInstance(SIGNATURE_SCHEME);
        verifier.setParameter(PSS_PARAMS);
        verifier.initVerify(partnerKey);
        verifier.update(body);
        return verifier.verify(Base64.getDecoder().decode(signatureHeader));
    }

    public boolean verifyMac(byte[] body, String timestamp, String macHeader, byte[] partnerSecret)
            throws GeneralSecurityException {
        Instant sent = Instant.ofEpochSecond(Long.parseLong(timestamp));
        Duration tolerance = properties.webhooks().inbound().tolerance();
        if (Duration.between(sent, Instant.now()).abs().compareTo(tolerance) > 0) {
            return false;
        }
        Mac mac = Mac.getInstance(properties.webhooks().inbound().macAlgorithm());
        mac.init(new SecretKeySpec(partnerSecret, mac.getAlgorithm()));
        mac.update(timestamp.getBytes(StandardCharsets.US_ASCII));
        mac.update((byte) '.');
        byte[] expected = mac.doFinal(body);
        return MessageDigest.isEqual(expected, HexFormat.of().parseHex(macHeader));
    }
}
