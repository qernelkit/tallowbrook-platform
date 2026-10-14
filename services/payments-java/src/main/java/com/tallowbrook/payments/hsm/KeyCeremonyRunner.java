package com.tallowbrook.payments.hsm;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.Provider;
import java.security.spec.ECGenParameterSpec;
import java.util.List;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

/**
 * Runs the quarterly key ceremony against the payments token. Started by two key custodians with
 * {@code --spring.profiles.active=key-ceremony} and the list of steps to perform, for example
 * {@code depot-readers vault settlement}. A step whose label already exists on the token is
 * skipped.
 */
@Component
@Profile("key-ceremony")
public class KeyCeremonyRunner implements CommandLineRunner {

    private static final Logger log = LoggerFactory.getLogger(KeyCeremonyRunner.class);

    public static final String BASE_DERIVATION_KEY_LABEL = "depot-readers-base";
    public static final String VAULT_KEK_LABEL = "card-vault-kek";
    public static final String SETTLEMENT_KEY_LABEL = "settlement-signing";
    private static final Path CEREMONY_OUT = Path.of("/var/lib/payments/ceremony");

    private final Provider hsm;

    public KeyCeremonyRunner(@Qualifier("paymentsHsm") Provider hsm) {
        this.hsm = hsm;
    }

    @Override
    public void run(String... args) throws Exception {
        List<String> steps = List.of(args);
        if (steps.isEmpty()) {
            log.warn("No ceremony steps given; nothing to do");
            return;
        }
        KeyStore token = KeyStore.getInstance("PKCS11", hsm);
        token.load(null, null);
        for (String step : steps) {
            switch (step) {
                case "depot-readers" ->
                        runOnce(
                                token,
                                BASE_DERIVATION_KEY_LABEL,
                                () -> generateDepotReaderBase(token));
                case "vault" -> runOnce(token, VAULT_KEK_LABEL, () -> generateVaultKek(token));
                case "settlement" ->
                        runOnce(token, SETTLEMENT_KEY_LABEL, this::generateSettlementKeys);
                default -> log.warn("Unknown ceremony step '{}', skipped", step);
            }
        }
    }

    private void runOnce(KeyStore token, String label, CeremonyStep step) throws Exception {
        if (token.containsAlias(label)) {
            log.info("Label {} already present on the token, step skipped", label);
            return;
        }
        step.run();
    }

    private void generateDepotReaderBase(KeyStore token) throws GeneralSecurityException {
        KeyGenerator bdkGenerator = KeyGenerator.getInstance("DESede", hsm);
        bdkGenerator.init(112);
        SecretKey base = bdkGenerator.generateKey();
        token.setEntry(BASE_DERIVATION_KEY_LABEL, new KeyStore.SecretKeyEntry(base), null);
        log.info("Depot reader base key stored under label {}", BASE_DERIVATION_KEY_LABEL);
    }

    private void generateVaultKek(KeyStore token) throws GeneralSecurityException {
        KeyGenerator vaultKekGenerator = KeyGenerator.getInstance("AES", hsm);
        vaultKekGenerator.init(256);
        SecretKey kek = vaultKekGenerator.generateKey();
        token.setEntry(VAULT_KEK_LABEL, new KeyStore.SecretKeyEntry(kek), null);
        log.info("Vault key generated with AES-256 under label {}", VAULT_KEK_LABEL);
    }

    /**
     * The private half stays on the token. The public half is written out for the issuing CA; ops
     * imports the issued certificate under the same label with keytool afterwards.
     */
    private void generateSettlementKeys() throws GeneralSecurityException, IOException {
        KeyPairGenerator settlementKeys = KeyPairGenerator.getInstance("EC", hsm);
        settlementKeys.initialize(new ECGenParameterSpec("secp384r1"));
        KeyPair pair = settlementKeys.generateKeyPair();
        Files.createDirectories(CEREMONY_OUT);
        Path out = CEREMONY_OUT.resolve(SETTLEMENT_KEY_LABEL + ".spki.der");
        Files.write(out, pair.getPublic().getEncoded());
        log.info("Settlement signing key created; public half written to {}", out);
    }

    @FunctionalInterface
    private interface CeremonyStep {
        void run() throws Exception;
    }
}
