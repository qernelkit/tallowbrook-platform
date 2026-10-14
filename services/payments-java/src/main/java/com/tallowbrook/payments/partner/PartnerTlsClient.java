package com.tallowbrook.payments.partner;

import com.tallowbrook.payments.config.PaymentsProperties;

import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.InputStream;
import java.net.http.HttpClient;
import java.nio.file.Files;
import java.security.GeneralSecurityException;
import java.security.KeyStore;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;

/** HTTP client for partner APIs, authenticated with the payments service certificate. */
@Component
public class PartnerTlsClient {

    private final PaymentsProperties properties;
    private volatile HttpClient client;

    public PartnerTlsClient(PaymentsProperties properties) {
        this.properties = properties;
    }

    public HttpClient client() throws GeneralSecurityException, IOException {
        HttpClient current = client;
        if (current == null) {
            synchronized (this) {
                if (client == null) {
                    client = build();
                }
                current = client;
            }
        }
        return current;
    }

    private HttpClient build() throws GeneralSecurityException, IOException {
        PaymentsProperties.Partners partners = properties.partners();
        SSLContext context = SSLContext.getInstance(properties.partners().tlsProtocol());
        context.init(
                identity().getKeyManagers(),
                PartnerTrust.trustManagers(
                                partners.truststore(), partners.truststorePassword().toCharArray())
                        .getTrustManagers(),
                null);
        return HttpClient.newBuilder()
                .sslContext(context)
                .connectTimeout(partners.timeout())
                .version(HttpClient.Version.HTTP_2)
                .build();
    }

    private KeyManagerFactory identity() throws GeneralSecurityException, IOException {
        PaymentsProperties.Signing signing = properties.signing();
        char[] password = signing.keystorePassword().toCharArray();
        KeyStore store = KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(signing.keystore())) {
            store.load(in, password);
        }
        KeyManagerFactory kmf =
                KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(store, password);
        return kmf;
    }
}
