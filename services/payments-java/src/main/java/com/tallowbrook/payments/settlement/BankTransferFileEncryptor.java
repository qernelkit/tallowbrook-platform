package com.tallowbrook.payments.settlement;

import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.HexFormat;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

/**
 * Harbor Bank transfer files. The bank's file specification (v3.2, section 4.2) fixes the IV for
 * every file and expects the body as base64 text between a header and a trailer line.
 */
@Component
public class BankTransferFileEncryptor {

    private static final byte[] BANK_FORMAT_IV =
            HexFormat.of().parseHex("3A7F0C52E1B94D68A20F5C1793E6B84D");
    private static final DateTimeFormatter HEADER_DATE = DateTimeFormatter.BASIC_ISO_DATE;
    private static final int LINE_WIDTH = 76;

    public String prepare(
            SecretKey bankKey, String senderId, LocalDate valueDate, byte[] transferFile)
            throws GeneralSecurityException {
        if (transferFile.length == 0) {
            throw new IllegalArgumentException("Empty transfer file");
        }
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, bankKey, new IvParameterSpec(BANK_FORMAT_IV));
        byte[] ciphertext = cipher.doFinal(transferFile);
        String body = Base64.getEncoder().encodeToString(ciphertext);
        return framed(senderId, valueDate, body);
    }

    private static String framed(String senderId, LocalDate valueDate, String body) {
        StringBuilder out = new StringBuilder();
        out.append("HDR|")
                .append(senderId)
                .append('|')
                .append(HEADER_DATE.format(valueDate))
                .append('\n');
        for (int i = 0; i < body.length(); i += LINE_WIDTH) {
            out.append(body, i, Math.min(body.length(), i + LINE_WIDTH)).append('\n');
        }
        out.append("TRL|").append(body.getBytes(StandardCharsets.US_ASCII).length).append('\n');
        return out.toString();
    }
}
