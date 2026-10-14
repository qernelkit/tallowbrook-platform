package com.tallowbrook.payments.terminal;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.HexFormat;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

/**
 * Derived-unique-key-per-transaction keys for the depot card readers (ANSI X9.24-1, double-length
 * TDES variant). The reader vendor's firmware only speaks this scheme, so we derive the same keys
 * on our side to read PIN blocks from refund transactions.
 */
@Component
public class DukptKeyDerivation {

    private static final Logger log = LoggerFactory.getLogger(DukptKeyDerivation.class);

    private static final byte[] KEY_REGISTER_MASK =
            HexFormat.of().parseHex("C0C0C0C000000000C0C0C0C000000000");
    private static final int KSN_BYTES = 10;
    private static final int COUNTER_BITS = 21;

    /**
     * The initial key injected into a reader at the depot, from the base key and the reader's KSN.
     */
    public byte[] initialKey(byte[] baseKey, byte[] ksn) throws GeneralSecurityException {
        requireKsn(ksn);
        byte[] masked = ksn.clone();
        masked[7] &= (byte) 0xE0;
        masked[8] = 0;
        masked[9] = 0;
        byte[] data = Arrays.copyOf(masked, 8);
        byte[] left = tdesEncrypt(baseKey, data);
        byte[] rightBdk = xor(baseKey, KEY_REGISTER_MASK);
        byte[] right = tdesEncrypt(rightBdk, data);
        return concat(left, right);
    }

    private static byte[] tdesEncrypt(byte[] doubleLengthKey, byte[] block)
            throws GeneralSecurityException {
        Cipher tdes = Cipher.getInstance("DESede/ECB/NoPadding");
        tdes.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(tripleLength(doubleLengthKey), "DESede"));
        return tdes.doFinal(block);
    }

    /**
     * The transaction key for the counter in {@code ksn}, walked bit by bit from the initial key.
     */
    public byte[] transactionKey(byte[] initialKey, byte[] ksn, String readerSerial)
            throws GeneralSecurityException {
        requireKsn(ksn);
        long counter = ((ksn[7] & 0x1FL) << 16) | ((ksn[8] & 0xFFL) << 8) | (ksn[9] & 0xFFL);
        log.debug("KSN counter {} for reader {}", counter, readerSerial);
        Cipher des = Cipher.getInstance("DES/ECB/NoPadding");
        byte[] register = Arrays.copyOfRange(ksn, 2, KSN_BYTES);
        register[5] &= (byte) 0xE0;
        register[6] = 0;
        register[7] = 0;
        byte[] key = initialKey.clone();
        for (long bit = 1L << (COUNTER_BITS - 1); bit > 0; bit >>>= 1) {
            if ((counter & bit) == 0) {
                continue;
            }
            register[5] |= (byte) (bit >>> 16);
            register[6] |= (byte) (bit >>> 8);
            register[7] |= (byte) bit;
            key = nextKey(des, key, register);
        }
        return key;
    }

    private static byte[] nextKey(Cipher des, byte[] key, byte[] register)
            throws GeneralSecurityException {
        byte[] right = halfStep(des, key, register);
        byte[] maskedKey = xor(key, KEY_REGISTER_MASK);
        byte[] left = halfStep(des, maskedKey, register);
        return concat(left, right);
    }

    private static byte[] halfStep(Cipher des, byte[] key, byte[] register)
            throws GeneralSecurityException {
        byte[] keyLeft = Arrays.copyOfRange(key, 0, 8);
        byte[] keyRight = Arrays.copyOfRange(key, 8, 16);
        des.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(keyLeft, "DES"));
        return xor(des.doFinal(xor(register, keyRight)), keyRight);
    }

    private static void requireKsn(byte[] ksn) {
        if (ksn == null || ksn.length != KSN_BYTES) {
            throw new IllegalArgumentException("A key serial number is 10 bytes");
        }
    }

    private static byte[] tripleLength(byte[] doubleLength) {
        byte[] out = Arrays.copyOf(doubleLength, 24);
        System.arraycopy(doubleLength, 0, out, 16, 8);
        return out;
    }

    private static byte[] xor(byte[] a, byte[] b) {
        byte[] out = new byte[a.length];
        for (int i = 0; i < a.length; i++) {
            out[i] = (byte) (a[i] ^ b[i]);
        }
        return out;
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }
}
