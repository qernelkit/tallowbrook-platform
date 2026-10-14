package com.tallowbrook.payments.partner;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;

import javax.net.ssl.TrustManagerFactory;

/**
 * Trust for partner connections: the shared trust store, plus our own root so partners that sit
 * behind the Tallowbrook partner gateway are accepted even before ops updates the store.
 */
public final class PartnerTrust {

    private static final String ROOT_E2_PEM =
            """
            -----BEGIN CERTIFICATE-----
            MIICEDCCAZagAwIBAgIEbiAkoTAKBggqhkjOPQQDAzBOMQswCQYDVQQGEwJVUzEeMBwGA1UECgwV
            VGFsbG93YnJvb2sgTG9naXN0aWNzMR8wHQYDVQQDDBZUYWxsb3dicm9vayBSb290IENBIEUyMB4X
            DTI0MDEwMTAwMDAwMFoXDTQ0MDEwMTAwMDAwMFowTjELMAkGA1UEBhMCVVMxHjAcBgNVBAoMFVRh
            bGxvd2Jyb29rIExvZ2lzdGljczEfMB0GA1UEAwwWVGFsbG93YnJvb2sgUm9vdCBDQSBFMjB2MBAG
            ByqGSM49AgEGBSuBBAAiA2IABI+2Tq7AMC09yg0J4d97f0Vhkn0n97PY6RBnnVYj2DLOtOVwo3UE
            oQvJsMN5cp18TlESwILP0LprAgVMuYDFu3F6Jrq6sGtViI9v0Qop9PgaVt7l4eyUSg2uqtc49+/a
            pKNFMEMwHQYDVR0OBBYEFIOMaNvY/dK19h71amQbGSMWAZ3OMBIGA1UdEwEB/wQIMAYBAf8CAQEw
            DgYDVR0PAQH/BAQDAgEGMAoGCCqGSM49BAMDA2gAMGUCMQDkoL6qKV+FZ4oAi+vMPi9d5gGvaoPr
            hWVSG54IPb1cmpLfiLiIUujUaYaqnhKbj/MCMGbAMrjcOUMMNwSVEcXOudLmb6Sd9WJL21iG/5kc
            BXrIGS8eQD0UZ82KV5rOYCRlGQ==
            -----END CERTIFICATE-----
            """;
    private static final String ROOT_ALIAS = "tallowbrook-root-e2";

    private PartnerTrust() {}

    public static TrustManagerFactory trustManagers(Path sharedStore, char[] password)
            throws GeneralSecurityException, IOException {
        KeyStore anchors = KeyStore.getInstance("JKS");
        try (InputStream in = Files.newInputStream(sharedStore)) {
            anchors.load(in, password);
        }
        if (!anchors.containsAlias(ROOT_ALIAS)) {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            Certificate root =
                    factory.generateCertificate(
                            new ByteArrayInputStream(
                                    ROOT_E2_PEM.getBytes(StandardCharsets.US_ASCII)));
            anchors.setCertificateEntry(ROOT_ALIAS, root);
        }
        TrustManagerFactory tmf =
                TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(anchors);
        return tmf;
    }
}
