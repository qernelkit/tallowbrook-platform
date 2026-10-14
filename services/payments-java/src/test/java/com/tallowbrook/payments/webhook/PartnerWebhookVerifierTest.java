package com.tallowbrook.payments.webhook;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.util.Base64;

class PartnerWebhookVerifierTest {

    private static final byte[] BODY =
            "{\"event\":\"delivery.completed\",\"parcel\":\"TB0012345678\"}"
                    .getBytes(StandardCharsets.UTF_8);

    private static KeyPair partner;
    private static String header;

    @BeforeAll
    static void signAsPartner() throws Exception {
        partner = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        Signature signer = Signature.getInstance(PartnerWebhookVerifier.SIGNATURE_SCHEME);
        signer.setParameter(PartnerWebhookVerifier.PSS_PARAMS);
        signer.initSign(partner.getPrivate());
        signer.update(BODY);
        header = Base64.getEncoder().encodeToString(signer.sign());
    }

    @Test
    void acceptsTheBodyThePartnerSigned() throws Exception {
        PartnerWebhookVerifier verifier = new PartnerWebhookVerifier(null, partner.getPublic());
        assertTrue(verifier.verifySignature(BODY, header));
    }

    @Test
    void rejectsAModifiedBody() throws Exception {
        PartnerWebhookVerifier verifier = new PartnerWebhookVerifier(null, partner.getPublic());
        byte[] modified = BODY.clone();
        modified[modified.length - 3] = '9';
        assertFalse(verifier.verifySignature(modified, header));
    }

    @Test
    void rejectsAMissingHeader() throws Exception {
        PartnerWebhookVerifier verifier = new PartnerWebhookVerifier(null, partner.getPublic());
        assertFalse(verifier.verifySignature(BODY, ""));
    }
}
