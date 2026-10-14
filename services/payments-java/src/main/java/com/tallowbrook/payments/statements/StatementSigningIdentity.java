package com.tallowbrook.payments.statements;

import com.tallowbrook.payments.config.PaymentsProperties;

import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

/** The payments service's own key and certificate, read once from the signing keystore. */
@Component
public class StatementSigningIdentity {

    private final PrivateKey key;
    private final X509Certificate chainHead;

    public StatementSigningIdentity(PaymentsProperties properties)
            throws GeneralSecurityException, IOException {
        PaymentsProperties.Signing signing = properties.signing();
        char[] password = signing.keystorePassword().toCharArray();
        KeyStore store = KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(signing.keystore())) {
            store.load(in, password);
        }
        this.key = (PrivateKey) store.getKey(signing.keyAlias(), password);
        this.chainHead = (X509Certificate) store.getCertificate(signing.keyAlias());
    }

    PrivateKey key() {
        return key;
    }

    X509Certificate chainHead() {
        return chainHead;
    }
}
