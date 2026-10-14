package com.tallowbrook.payments.merchant;

import com.tallowbrook.payments.config.PaymentsProperties;
import com.tallowbrook.payments.partner.PartnerTlsClient;

import org.springframework.stereotype.Component;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.List;

/**
 * Client for the internal merchant CA. It takes the merchant id and the encoded public key over the
 * mutually authenticated partner channel and returns the issued chain, leaf first.
 */
@Component
public class MerchantCaClient {

    private final PartnerTlsClient partners;
    private final URI caUrl;

    public MerchantCaClient(PartnerTlsClient partners, PaymentsProperties properties) {
        this.partners = partners;
        this.caUrl = properties.merchants().caUrl();
    }

    public Certificate[] issue(String merchantId, PublicKey merchantKey)
            throws IOException, GeneralSecurityException {
        HttpRequest request =
                HttpRequest.newBuilder(caUrl.resolve(merchantId + "/issue"))
                        .header("Content-Type", "application/octet-stream")
                        .POST(HttpRequest.BodyPublishers.ofByteArray(merchantKey.getEncoded()))
                        .build();
        HttpResponse<byte[]> response;
        try {
            response = partners.client().send(request, HttpResponse.BodyHandlers.ofByteArray());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Interrupted while waiting for the merchant CA", e);
        }
        if (response.statusCode() != 200) {
            throw new IOException("Merchant CA answered HTTP " + response.statusCode());
        }
        CertificateFactory parser = CertificateFactory.getInstance("X.509");
        List<? extends Certificate> chain =
                List.copyOf(parser.generateCertificates(new ByteArrayInputStream(response.body())));
        return chain.toArray(new Certificate[0]);
    }
}
