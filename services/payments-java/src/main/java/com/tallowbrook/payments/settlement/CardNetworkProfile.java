package com.tallowbrook.payments.settlement;

/**
 * Clearing-file formats of the card networks we settle with. Each network dictates its own
 * transformation and key length in its clearing specification.
 */
public enum CardNetworkProfile {
    KESTREL("AES/ECB/PKCS5Padding", 16),
    OSPREY(null, 0);

    private final String transformation;
    private final int keyLength;

    CardNetworkProfile(String transformation, int keyLength) {
        this.transformation = transformation;
        this.keyLength = keyLength;
    }

    public String transformation() {
        return transformation;
    }

    public int keyLength() {
        return keyLength;
    }

    /** Osprey takes clearing files in clear over its private link. */
    public boolean sealed() {
        return transformation != null;
    }
}
