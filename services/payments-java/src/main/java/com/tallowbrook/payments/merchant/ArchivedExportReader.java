package com.tallowbrook.payments.merchant;

import com.tallowbrook.payments.config.PaymentsProperties;

import org.springframework.stereotype.Component;

import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Reads merchant exports written by the 2011 merchant portal, which merchants still upload when
 * they dispute old statements. Version 1 files start with "TBX1" and an 8-byte salt and are
 * protected by the merchant's portal password; version 0 files have no header and use the portal's
 * own export key.
 */
@Component
public class ArchivedExportReader {

    private static final String V1_PBE = "PBEWithMD5AndDES";
    private static final int V1_ITERATIONS = 1000;
    private static final byte[] V1_MAGIC = {'T', 'B', 'X', '1'};

    private final byte[] v0ExportKey;

    public ArchivedExportReader(PaymentsProperties properties) {
        String configured = properties.merchants().v0ExportKey();
        this.v0ExportKey =
                configured == null || configured.isEmpty()
                        ? new byte[0]
                        : Base64.getDecoder().decode(configured);
    }

    public byte[] read(byte[] file, char[] portalPassword) throws GeneralSecurityException {
        if (file.length > 12 && Arrays.equals(Arrays.copyOf(file, 4), V1_MAGIC)) {
            return readV1(Arrays.copyOfRange(file, 4, file.length), portalPassword);
        }
        return readV0(file);
    }

    private byte[] readV1(byte[] body, char[] portalPassword) throws GeneralSecurityException {
        byte[] salt = Arrays.copyOf(body, 8);
        SecretKeyFactory factory = SecretKeyFactory.getInstance(V1_PBE);
        SecretKey key = factory.generateSecret(new PBEKeySpec(portalPassword));
        Cipher cipher = Cipher.getInstance(V1_PBE);
        cipher.init(Cipher.DECRYPT_MODE, key, new PBEParameterSpec(salt, V1_ITERATIONS));
        return cipher.doFinal(body, 8, body.length - 8);
    }

    private byte[] readV0(byte[] file) throws GeneralSecurityException {
        if (v0ExportKey.length == 0) {
            throw new IllegalStateException(
                    "Version 0 exports need tallowbrook.payments.merchants.v0-export-key");
        }
        Cipher v0 = Cipher.getInstance("Blowfish");
        v0.init(Cipher.DECRYPT_MODE, new SecretKeySpec(v0ExportKey, "Blowfish"));
        return v0.doFinal(file);
    }
}
