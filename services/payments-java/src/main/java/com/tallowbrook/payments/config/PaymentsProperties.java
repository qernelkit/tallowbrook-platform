package com.tallowbrook.payments.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.net.URI;
import java.nio.file.Path;
import java.time.Duration;

/**
 * Everything under {@code tallowbrook.payments} in application.yml and the production overrides.
 */
@ConfigurationProperties(prefix = "tallowbrook.payments")
public record PaymentsProperties(
        Hsm hsm,
        Signing signing,
        Tokens tokens,
        Webhooks webhooks,
        Statements statements,
        Partners partners,
        Acquirers acquirers,
        Archive archive,
        Card card,
        Merchants merchants,
        Ledger ledger,
        Fx fx,
        String referenceSalt) {

    public record Hsm(Path pkcs11Config) {}

    public record Signing(Path keystore, String keyAlias, String keystorePassword) {}

    public record Tokens(URI issuer, Path tokenSigningKey, Duration ttl) {}

    public record Webhooks(Inbound inbound) {

        public record Inbound(String macAlgorithm, Duration tolerance) {}
    }

    public record Statements(String digestAlgorithm, String bankCode) {}

    public record Partners(
            String tlsProtocol, Path truststore, String truststorePassword, Duration timeout) {}

    public record Acquirers(Northgate northgate) {

        public record Northgate(String batchCipher, String trailerChecksum, Path uploadDir) {}
    }

    public record Archive(Path escrowPublicKey, Duration retention) {}

    public record Card(String panIndexKey, String tokenizationKey) {}

    public record Merchants(int[] refRoundKeys, String v0ExportKey, URI caUrl) {}

    public record Ledger(String sealPublicKey) {}

    public record Fx(String ecbReferenceRatesUrl, Duration refresh) {}
}
