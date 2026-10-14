package com.tallowbrook.payments.card;

import java.util.Set;

/** Input checks for primary account numbers before they reach the vault. */
public final class PanChecks {

    private static final Set<String> TEST_BIN_PREFIXES = Set.of("400000", "411111", "555555");

    private PanChecks() {}

    public static boolean digitsOnly(String pan) {
        return pan != null && !pan.isEmpty() && pan.chars().allMatch(Character::isDigit);
    }

    public static boolean plausibleLength(String pan) {
        return pan.length() >= 13 && pan.length() <= 19;
    }

    /** Mod-10 check digit over the full number. */
    public static boolean luhnValid(String pan) {
        if (!digitsOnly(pan)) {
            return false;
        }
        int sum = 0;
        boolean doubleIt = false;
        for (int i = pan.length() - 1; i >= 0; i--) {
            int d = pan.charAt(i) - '0';
            if (doubleIt) {
                d *= 2;
                if (d > 9) {
                    d -= 9;
                }
            }
            sum += d;
            doubleIt = !doubleIt;
        }
        return sum % 10 == 0;
    }

    public static String bin(String pan) {
        return pan.substring(0, 6);
    }

    public static boolean isTestCard(String pan) {
        return TEST_BIN_PREFIXES.contains(bin(pan));
    }

    public static String masked(String pan) {
        return bin(pan) + "*".repeat(pan.length() - 10) + pan.substring(pan.length() - 4);
    }
}
