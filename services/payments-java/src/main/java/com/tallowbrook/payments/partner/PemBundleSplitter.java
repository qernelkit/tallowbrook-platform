package com.tallowbrook.payments.partner;

import java.util.ArrayList;
import java.util.List;

/**
 * Partners upload their certificate chains as one text file. This only cuts the upload into blocks
 * for the review screen; parsing and validation happen in the onboarding service.
 */
public final class PemBundleSplitter {

    private static final String BEGIN_CERT = "-----BEGIN CERTIFICATE-----";
    private static final String END_CERT = "-----END CERTIFICATE-----";
    private static final int MAX_BLOCKS = 10;

    private PemBundleSplitter() {}

    public static List<String> split(String upload) {
        List<String> blocks = new ArrayList<>();
        int from = 0;
        while (blocks.size() < MAX_BLOCKS) {
            int start = upload.indexOf(BEGIN_CERT, from);
            if (start < 0) {
                break;
            }
            int end = upload.indexOf(END_CERT, start);
            if (end < 0) {
                throw new IllegalArgumentException("Unterminated block at offset " + start);
            }
            blocks.add(upload.substring(start, end + END_CERT.length()));
            from = end + END_CERT.length();
        }
        return blocks;
    }
}
