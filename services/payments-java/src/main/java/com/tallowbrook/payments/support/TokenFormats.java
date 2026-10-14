package com.tallowbrook.payments.support;

import java.nio.ByteBuffer;
import java.util.Base64;
import java.util.UUID;

/** Formatting helpers for references that appear on paper and in merchant-facing screens. */
public final class TokenFormats {

    private TokenFormats() {}

    /** A 22-character public reference for a UUID. */
    public static String publicReference(UUID id) {
        byte[] raw =
                ByteBuffer.allocate(16)
                        .putLong(id.getMostSignificantBits())
                        .putLong(id.getLeastSignificantBits())
                        .array();
        return Base64.getUrlEncoder().withoutPadding().encodeToString(raw);
    }

    /** The signature line printed at the bottom of paper statements. */
    public static String signatureLine(String merchantName) {
        return "Authorised signature: ____________________  (" + merchantName + ")";
    }

    public static String groupDigits(String digits) {
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < digits.length(); i++) {
            if (i > 0 && i % 4 == 0) {
                out.append(' ');
            }
            out.append(digits.charAt(i));
        }
        return out.toString();
    }
}
