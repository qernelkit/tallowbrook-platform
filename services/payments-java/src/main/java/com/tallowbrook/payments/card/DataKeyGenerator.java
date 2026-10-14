package com.tallowbrook.payments.card;

import org.springframework.stereotype.Component;

import java.security.NoSuchAlgorithmException;
import java.util.UUID;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

/** A fresh data key for each batch of vault rows; it is stored wrapped under the vault KEK. */
@Component
public class DataKeyGenerator {

    public record BatchKey(String keyId, SecretKey key) {}

    public BatchKey newBatchKey() throws NoSuchAlgorithmException {
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        return new BatchKey("dk-" + UUID.randomUUID(), generator.generateKey());
    }
}
