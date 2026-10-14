package com.tallowbrook.payments.webhook;

import com.tallowbrook.payments.config.PaymentsProperties;

import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Signature;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;

/**
 * Signs the webhooks we send to merchants. Merchants verify against the certificate published in
 * the developer portal, which belongs to the payments service key pair.
 */
@Component
public class OutboundWebhookSigner {

    private static final String SIGNATURE_ALG = "SHA256withRSA";

    private final PrivateKey webhookKey;

    public OutboundWebhookSigner(PaymentsProperties properties)
            throws GeneralSecurityException, IOException {
        PaymentsProperties.Signing signing = properties.signing();
        char[] password = signing.keystorePassword().toCharArray();
        KeyStore store = KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(signing.keystore())) {
            store.load(in, password);
        }
        this.webhookKey = (PrivateKey) store.getKey(signing.keyAlias(), password);
    }

    /** Value of the {@code Tallowbrook-Signature} header: {@code t=<epoch>,v2=<base64>}. */
    public String signatureHeader(byte[] payload) throws GeneralSecurityException {
        long timestamp = Instant.now().getEpochSecond();
        byte[] signedContent = signedContent(timestamp, payload);
        Signature signer = Signature.getInstance(SIGNATURE_ALG);
        signer.initSign(webhookKey);
        signer.update(signedContent);
        String header = Base64.getEncoder().encodeToString(signer.sign());
        return "t=" + timestamp + ",v2=" + header;
    }

    private static byte[] signedContent(long timestamp, byte[] payload) {
        byte[] prefix = (timestamp + ".").getBytes(StandardCharsets.US_ASCII);
        byte[] out = Arrays.copyOf(prefix, prefix.length + payload.length);
        System.arraycopy(payload, 0, out, prefix.length, payload.length);
        return out;
    }
}
