package com.tallowbrook.payments.card;

import org.springframework.stereotype.Component;

import java.security.GeneralSecurityException;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

/**
 * Builds ISO 9564 format 0 PIN blocks for card-present refunds at depot terminals and enciphers
 * them under the terminal's PIN key before they leave the service.
 */
@Component
public class PinBlockFormatter {

    private static final int ISO_9564_FORMAT_0 = 0;
    private static final String PIN_ENCIPHERMENT = "DESede/ECB/NoPadding";
    private static final int BLOCK = 8;

    public byte[] encipher(String pin, String pan, SecretKey terminalPinKey)
            throws GeneralSecurityException {
        byte[] clear = format0(pin, pan);
        try {
            Cipher tdes = Cipher.getInstance(PIN_ENCIPHERMENT);
            tdes.init(Cipher.ENCRYPT_MODE, terminalPinKey);
            return tdes.doFinal(clear);
        } finally {
            Arrays.fill(clear, (byte) 0);
        }
    }

    byte[] format0(String pin, String pan) {
        if (pin == null
                || pin.length() < 4
                || pin.length() > 12
                || !pin.chars().allMatch(Character::isDigit)) {
            throw new IllegalArgumentException("PIN must be 4 to 12 digits");
        }
        byte[] pinField = new byte[BLOCK];
        Arrays.fill(pinField, (byte) 0xFF);
        if (!PanChecks.luhnValid(pan)) {
            throw new IllegalArgumentException("Card number fails the check digit");
        }
        pinField[0] = (byte) ((ISO_9564_FORMAT_0 << 4) | pin.length());
        for (int i = 0; i < pin.length(); i++) {
            int nibble = pin.charAt(i) - '0';
            int pos = i + 2;
            if (pos % 2 == 0) {
                pinField[pos / 2] = (byte) ((nibble << 4) | (pinField[pos / 2] & 0x0F));
            } else {
                pinField[pos / 2] = (byte) ((pinField[pos / 2] & 0xF0) | nibble);
            }
        }
        byte[] panField = panField(pan);
        byte[] block = new byte[BLOCK];
        for (int i = 0; i < BLOCK; i++) {
            block[i] = (byte) (pinField[i] ^ panField[i]);
        }
        return block;
    }

    /** Four zero nibbles, then the twelve rightmost PAN digits excluding the check digit. */
    private static byte[] panField(String pan) {
        String digits = pan.substring(pan.length() - 13, pan.length() - 1);
        byte[] field = new byte[BLOCK];
        for (int i = 0; i < digits.length(); i += 2) {
            int hi = digits.charAt(i) - '0';
            int lo = digits.charAt(i + 1) - '0';
            field[2 + i / 2] = (byte) ((hi << 4) | lo);
        }
        return field;
    }
}
