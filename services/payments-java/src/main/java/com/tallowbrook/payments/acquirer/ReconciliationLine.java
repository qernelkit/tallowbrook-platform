package com.tallowbrook.payments.acquirer;

import java.math.BigDecimal;
import java.time.LocalDate;

/**
 * One line of the Harbor Bank reconciliation file: {@code date;merchant;reference;amount;currency}.
 */
public record ReconciliationLine(
        LocalDate valueDate,
        String merchantId,
        String reference,
        BigDecimal amount,
        String currency) {

    public static ReconciliationLine parse(String line) {
        String[] f = line.split(";", -1);
        if (f.length != 5) {
            throw new IllegalArgumentException("Expected 5 fields, got " + f.length);
        }
        return new ReconciliationLine(
                LocalDate.parse(f[0]),
                f[1].trim(),
                f[2].trim(),
                new BigDecimal(f[3].trim()),
                f[4].trim());
    }
}
