package com.tallowbrook.payments.card;

import com.tallowbrook.payments.config.PaymentsProperties;
import com.tallowbrook.payments.hsm.KeyCeremonyRunner;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyStore;
import java.security.Provider;
import java.util.Base64;

import javax.crypto.SecretKey;

/**
 * Where the card vault's keys come from: the vault key-encryption key never leaves the payments
 * token; the lookup-index and tokenization keys are injected by the deployment from the secret
 * store.
 */
@Component
public class CardVaultKeys {

    private final KeyStore token;
    private final byte[] panIndexKey;
    private final byte[] tokenizationKey;

    public CardVaultKeys(@Qualifier("paymentsHsm") Provider hsm, PaymentsProperties properties)
            throws GeneralSecurityException, IOException {
        this.token = KeyStore.getInstance("PKCS11", hsm);
        token.load(null, null);
        this.panIndexKey = Base64.getDecoder().decode(properties.card().panIndexKey());
        this.tokenizationKey = Base64.getDecoder().decode(properties.card().tokenizationKey());
    }

    public SecretKey vaultKek() throws GeneralSecurityException {
        Key key = token.getKey(KeyCeremonyRunner.VAULT_KEK_LABEL, null);
        if (!(key instanceof SecretKey kek)) {
            throw new IllegalStateException("Vault KEK missing from the token");
        }
        return kek;
    }

    byte[] panIndexKey() {
        return panIndexKey.clone();
    }

    byte[] tokenizationKey() {
        return tokenizationKey.clone();
    }
}
