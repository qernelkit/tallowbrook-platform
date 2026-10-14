package com.tallowbrook.payments.hsm;

/** Algorithm names for operations that run inside the payments HSM. */
public final class HsmAlgorithms {

    /** Settlement files are signed with the token-resident P-384 key from the key ceremony. */
    public static final String SETTLEMENT_SIGNATURE = "SHA384withECDSA";

    private HsmAlgorithms() {}
}
