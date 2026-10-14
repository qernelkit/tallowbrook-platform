package com.tallowbrook.payments.payouts;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.LocalDate;

/**
 * One line of a driver payout run, mapped onto the bank's payout file layout (column names follow
 * the bank's field names).
 */
@Entity
@Table(name = "PAYOUT_LINES")
public class PayoutLine {

    @Id @GeneratedValue private Long id;

    @Column(name = "RUN_ID", nullable = false, length = 32)
    private String runId;

    @Column(name = "DRIVER_ID", nullable = false, length = 32)
    private String driverId;

    @Column(name = "IBAN", nullable = false, length = 34)
    private String iban;

    @Column(name = "AMOUNT_MINOR", nullable = false)
    private long amountMinor;

    @Column(name = "CURRENCY", nullable = false, length = 3)
    private String currency;

    @Column(name = "VALUE_DATE", nullable = false)
    private LocalDate valueDate;

    @Column(name = "LINE_DES", length = 140)
    private String description;

    protected PayoutLine() {}

    public PayoutLine(
            String runId,
            String driverId,
            String iban,
            long amountMinor,
            String currency,
            LocalDate valueDate,
            String description) {
        if (amountMinor <= 0) {
            throw new IllegalArgumentException("Payout amount must be positive");
        }
        this.runId = runId;
        this.driverId = driverId;
        this.iban = iban;
        this.amountMinor = amountMinor;
        this.currency = currency;
        this.valueDate = valueDate;
        this.description =
                description == null
                        ? null
                        : description.substring(0, Math.min(140, description.length()));
    }

    public String getRunId() {
        return runId;
    }

    public String getDriverId() {
        return driverId;
    }

    public String getIban() {
        return iban;
    }

    public long getAmountMinor() {
        return amountMinor;
    }

    public String getCurrency() {
        return currency;
    }

    public LocalDate getValueDate() {
        return valueDate;
    }

    public String getDescription() {
        return description;
    }
}
