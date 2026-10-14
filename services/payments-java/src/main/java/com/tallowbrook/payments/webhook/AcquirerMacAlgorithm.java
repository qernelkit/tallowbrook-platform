package com.tallowbrook.payments.webhook;

/** MAC each acquirer puts on its settlement callbacks, as stated in its integration guide. */
public enum AcquirerMacAlgorithm {
    HARBOR_BANK("HmacSHA256"),
    NORTHGATE("HmacSHA1");

    private final String macName;

    AcquirerMacAlgorithm(String macName) {
        this.macName = macName;
    }

    public String macName() {
        return macName;
    }
}
