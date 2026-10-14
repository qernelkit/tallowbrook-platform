package com.tallowbrook.payments.webhook;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/**
 * Version 1 of the partner signature header, still sent by two regional partners whose SDK predates
 * v2. The v1 SDK computes the keyed hash itself, so this mirrors it step for step to stay
 * byte-compatible with what they send.
 */
public final class PartnerSignatureV1 {

    private static final int BLOCK_SIZE = 64;
    private static final String HEADER_PREFIX = "v1=";

    private PartnerSignatureV1() {}

    public static boolean matches(byte[] partnerSecret, String body, String header)
            throws NoSuchAlgorithmException {
        if (header == null || !header.startsWith(HEADER_PREFIX)) {
            return false;
        }
        byte[] expected = keyedHash(partnerSecret, body.getBytes(StandardCharsets.UTF_8));
        byte[] provided = HexFormat.of().parseHex(header.substring(HEADER_PREFIX.length()));
        return MessageDigest.isEqual(expected, provided);
    }

    static byte[] keyedHash(byte[] key, byte[] message) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] block = new byte[BLOCK_SIZE];
        if (key.length > BLOCK_SIZE) {
            byte[] shortened = md.digest(key);
            System.arraycopy(shortened, 0, block, 0, shortened.length);
        } else {
            System.arraycopy(key, 0, block, 0, key.length);
        }
        byte[] ipad = new byte[BLOCK_SIZE];
        byte[] opad = new byte[BLOCK_SIZE];
        for (int i = 0; i < BLOCK_SIZE; i++) {
            ipad[i] = (byte) (block[i] ^ 0x36);
            opad[i] = (byte) (block[i] ^ 0x5c);
        }
        md.update(ipad);
        byte[] inner = md.digest(message);
        md.update(opad);
        return md.digest(inner);
    }
}
