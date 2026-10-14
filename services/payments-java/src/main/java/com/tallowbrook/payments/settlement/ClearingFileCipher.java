package com.tallowbrook.payments.settlement;

import org.springframework.stereotype.Component;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.util.zip.CRC32;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

/**
 * Prepares clearing files for the card networks: the body in the network's format, followed by an
 * 8-byte trailer with the CRC-32 of the clearing records, which the network checks after reading
 * the body back.
 */
@Component
public class ClearingFileCipher {

    public byte[] prepare(CardNetworkProfile profile, SecretKey networkKey, byte[] clearingRecords)
            throws GeneralSecurityException {
        requireKeyLength(profile, networkKey);
        CRC32 trailer = new CRC32();
        trailer.update(clearingRecords);
        if (profile.sealed()) {
            Cipher cipher = Cipher.getInstance(profile.transformation());
            cipher.init(Cipher.ENCRYPT_MODE, networkKey);
            return withTrailer(cipher.doFinal(clearingRecords), trailer.getValue());
        }
        return withTrailer(clearingRecords, trailer.getValue());
    }

    private static void requireKeyLength(CardNetworkProfile profile, SecretKey networkKey) {
        if (!profile.sealed()) {
            return;
        }
        byte[] encoded = networkKey.getEncoded();
        if (encoded != null && encoded.length != profile.keyLength()) {
            throw new IllegalArgumentException(
                    "Key length does not match the " + profile + " profile");
        }
    }

    private static byte[] withTrailer(byte[] body, long checksum) {
        return ByteBuffer.allocate(body.length + Long.BYTES).put(body).putLong(checksum).array();
    }
}
