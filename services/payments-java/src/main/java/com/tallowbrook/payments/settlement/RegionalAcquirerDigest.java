package com.tallowbrook.payments.settlement;

import org.bouncycastle.crypto.digests.GOST3411_2012_256Digest;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HexFormat;

/**
 * The regional acquirer accepts a settlement file only with a GOST R 34.11-2012 (256-bit) hash of
 * it in the upload form, lower-case hex.
 */
@Component
public class RegionalAcquirerDigest {

    private static final int CHUNK = 8192;

    public String hashOf(Path settlementFile) throws IOException {
        GOST3411_2012_256Digest hasher = new GOST3411_2012_256Digest();
        byte[] buffer = new byte[CHUNK];
        try (InputStream in = Files.newInputStream(settlementFile)) {
            int read;
            while ((read = in.read(buffer)) > 0) {
                hasher.update(buffer, 0, read);
            }
        }
        byte[] out = new byte[hasher.getDigestSize()];
        hasher.doFinal(out, 0);
        return HexFormat.of().formatHex(out);
    }
}
