package com.tallowbrook.payments.settlement;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;

/** Manifest written next to each archived day: one line per file with its size and content hash. */
public final class ArchiveManifest {

    private static final String MANIFEST_DIGEST = "SHA3-256";

    public record Entry(String name, long size, String contentHash) {

        String line() {
            return contentHash + "  " + size + "  " + name;
        }
    }

    private final List<Entry> entries = new ArrayList<>();
    private final Instant createdAt = Instant.now();

    public void add(Path file) throws IOException, NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance(MANIFEST_DIGEST);
        try (InputStream in = Files.newInputStream(file)) {
            byte[] buffer = new byte[8192];
            int read;
            while ((read = in.read(buffer)) > 0) {
                md.update(buffer, 0, read);
            }
        }
        entries.add(
                new Entry(
                        file.getFileName().toString(),
                        Files.size(file),
                        HexFormat.of().formatHex(md.digest())));
    }

    public List<Entry> entries() {
        return List.copyOf(entries);
    }

    public String render() {
        StringBuilder out = new StringBuilder("# created ").append(createdAt).append('\n');
        entries.forEach(e -> out.append(e.line()).append('\n'));
        return out.toString();
    }
}
