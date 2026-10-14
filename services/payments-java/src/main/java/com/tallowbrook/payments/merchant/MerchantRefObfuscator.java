package com.tallowbrook.payments.merchant;

import com.tallowbrook.payments.config.PaymentsProperties;

import org.springframework.stereotype.Component;

import java.util.Locale;

/**
 * Turns internal merchant ids into the public references printed on invoices and back, so that
 * references do not reveal how many merchants we have. The mapping is a fixed permutation of the
 * 64-bit id space keyed by the round keys from configuration.
 */
@Component
public class MerchantRefObfuscator {

    private static final int ROUNDS = 4;

    private final int[] roundKeys;

    public MerchantRefObfuscator(PaymentsProperties properties) {
        int[] configured = properties.merchants().refRoundKeys();
        if (configured == null || configured.length != ROUNDS) {
            throw new IllegalStateException(
                    "Exactly " + ROUNDS + " merchant reference round keys are required");
        }
        this.roundKeys = configured.clone();
    }

    public String toPublicRef(long merchantId) {
        return "M" + Long.toUnsignedString(permute(merchantId, false), 36).toUpperCase(Locale.ROOT);
    }

    public long fromPublicRef(String reference) {
        if (reference == null || !reference.startsWith("M")) {
            throw new IllegalArgumentException("Not a merchant reference: " + reference);
        }
        return permute(
                Long.parseUnsignedLong(reference.substring(1).toLowerCase(Locale.ROOT), 36), true);
    }

    private long permute(long block, boolean inverse) {
        int left = (int) (block >>> 32);
        int right = (int) block;
        if (inverse) {
            int t = left;
            left = right;
            right = t;
        }
        for (int i = 0; i < ROUNDS; i++) {
            int round = inverse ? ROUNDS - 1 - i : i;
            left ^= roundFunction(right, roundKeys[round]);
            int t = left;
            left = right;
            right = t;
        }
        if (inverse) {
            int t = left;
            left = right;
            right = t;
        }
        return ((long) left << 32) | (right & 0xFFFFFFFFL);
    }

    private static int roundFunction(int half, int roundKey) {
        return Integer.rotateLeft(half * 0x9E3779B1, 13) ^ roundKey;
    }
}
