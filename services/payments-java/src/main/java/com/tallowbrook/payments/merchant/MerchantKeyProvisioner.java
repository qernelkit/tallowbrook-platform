package com.tallowbrook.payments.merchant;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.cert.Certificate;

/**
 * Creates the key pair a merchant uses to sign API requests and hands it over as a password
 * protected download. We keep only the certificate; the private key leaves with the download.
 */
@Service
public class MerchantKeyProvisioner {

    private static final Logger log = LoggerFactory.getLogger(MerchantKeyProvisioner.class);
    private static final String MERCHANT_KEY_ALGORITHM = "RSA";
    private static final int MERCHANT_KEY_BITS = 3072;
    private static final String ENTRY_ALIAS = "merchant-api";

    private final MerchantCaClient ca;

    public MerchantKeyProvisioner(MerchantCaClient ca) {
        this.ca = ca;
    }

    public byte[] provision(String merchantId, char[] downloadPassword)
            throws GeneralSecurityException, IOException {
        if (downloadPassword.length < 12) {
            throw new IllegalArgumentException("Download password must be at least 12 characters");
        }
        KeyPairGenerator generator = KeyPairGenerator.getInstance(MERCHANT_KEY_ALGORITHM);
        generator.initialize(MERCHANT_KEY_BITS);
        KeyPair merchantKeys = generator.generateKeyPair();
        Certificate[] chain = ca.issue(merchantId, merchantKeys.getPublic());

        KeyStore bundle = KeyStore.getInstance("PKCS12");
        bundle.load(null, null);
        bundle.setKeyEntry(ENTRY_ALIAS, merchantKeys.getPrivate(), downloadPassword, chain);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        bundle.store(out, downloadPassword);
        log.info("Provisioned API credentials for merchant {}", merchantId);
        return out.toByteArray();
    }
}
