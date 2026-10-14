package com.tallowbrook.payments.webhook;

import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Throwaway callback keys for the partner sandbox, one per sandbox merchant, regenerated whenever
 * the sandbox restarts.
 */
@Component
@Profile("sandbox")
public class SandboxCallbackKeys {

    private final Map<String, KeyPair> byMerchant = new ConcurrentHashMap<>();

    public KeyPair forMerchant(String merchantId) {
        return byMerchant.computeIfAbsent(merchantId, id -> generate());
    }

    private static KeyPair generate() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
            return generator.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
