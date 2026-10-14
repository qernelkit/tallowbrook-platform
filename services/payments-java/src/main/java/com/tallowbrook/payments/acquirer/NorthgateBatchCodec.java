package com.tallowbrook.payments.acquirer;

import com.tallowbrook.payments.config.PaymentsProperties;

import org.springframework.stereotype.Component;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.zip.CRC32;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

/**
 * Northgate batch files: an 8-byte IV, the body in the cipher their interface specification names,
 * and a 4-byte trailer checksum of the clear body.
 */
@Component
public class NorthgateBatchCodec {

    private static final int IV_BYTES = 8;

    private final PaymentsProperties properties;
    private final SecureRandom random;

    public NorthgateBatchCodec(PaymentsProperties properties, SecureRandom paymentsRandom) {
        this.properties = properties;
        this.random = paymentsRandom;
    }

    public byte[] encode(byte[] batch, SecretKey batchKey) throws GeneralSecurityException {
        byte[] iv = new byte[IV_BYTES];
        random.nextBytes(iv);
        Cipher cipher = Cipher.getInstance(properties.acquirers().northgate().batchCipher());
        cipher.init(Cipher.ENCRYPT_MODE, batchKey, new IvParameterSpec(iv));
        byte[] body = cipher.doFinal(batch);
        return ByteBuffer.allocate(IV_BYTES + body.length + Integer.BYTES)
                .put(iv)
                .put(body)
                .putInt((int) trailer(batch))
                .array();
    }

    public byte[] decode(byte[] file, SecretKey batchKey) throws GeneralSecurityException {
        if (file.length < IV_BYTES + Integer.BYTES + 8) {
            throw new IllegalArgumentException("Batch file too short");
        }
        byte[] iv = Arrays.copyOf(file, IV_BYTES);
        int bodyLength = file.length - IV_BYTES - Integer.BYTES;
        Cipher cipher = Cipher.getInstance(properties.acquirers().northgate().batchCipher());
        cipher.init(Cipher.DECRYPT_MODE, batchKey, new IvParameterSpec(iv));
        byte[] batch = cipher.doFinal(file, IV_BYTES, bodyLength);
        int expected = ByteBuffer.wrap(file, IV_BYTES + bodyLength, Integer.BYTES).getInt();
        if ((int) trailer(batch) != expected) {
            throw new IllegalArgumentException("Batch trailer does not match the body");
        }
        return batch;
    }

    private long trailer(byte[] clear) {
        if (!"CRC32".equals(properties.acquirers().northgate().trailerChecksum())) {
            throw new IllegalStateException("Unsupported trailer checksum");
        }
        CRC32 crc = new CRC32();
        crc.update(clear);
        return crc.getValue();
    }
}
