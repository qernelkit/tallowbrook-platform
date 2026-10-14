package com.tallowbrook.payments.settlement;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.zip.Adler32;
import java.util.zip.CRC32C;
import java.util.zip.Checksum;

/**
 * Change detection for settlement files: before a re-send we compare cheap checksums with what the
 * object store already holds, so unchanged files are not uploaded twice.
 */
public final class FileIntegrityChecks {

    private FileIntegrityChecks() {}

    /** Quick local comparison between two runs of the same job. */
    public static long adler(Path file) throws IOException {
        Adler32 adler = new Adler32();
        return feed(adler, file);
    }

    /** Matches the object store's crc32c metadata field. */
    public static long crc32c(Path file) throws IOException {
        CRC32C crc = new CRC32C();
        return feed(crc, file);
    }

    public static boolean unchanged(Path file, long storedCrc32c) throws IOException {
        return crc32c(file) == storedCrc32c;
    }

    private static long feed(Checksum checksum, Path file) throws IOException {
        byte[] buffer = new byte[16 * 1024];
        try (InputStream in = Files.newInputStream(file)) {
            int read;
            while ((read = in.read(buffer)) > 0) {
                checksum.update(buffer, 0, read);
            }
        }
        return checksum.getValue();
    }
}
