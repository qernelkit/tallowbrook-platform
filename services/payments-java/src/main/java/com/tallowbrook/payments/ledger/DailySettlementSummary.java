package com.tallowbrook.payments.ledger;

import java.nio.charset.StandardCharsets;
import java.time.LocalDate;
import java.util.Map;
import java.util.TreeMap;

/** Totals per currency for one business day, as reported to the ledger service. */
public record DailySettlementSummary(
        LocalDate businessDate, int batchCount, Map<String, Long> totalsMinorUnits) {

    public DailySettlementSummary {
        if (batchCount < 0) {
            throw new IllegalArgumentException("batchCount must not be negative");
        }
        totalsMinorUnits = Map.copyOf(totalsMinorUnits);
    }

    /** Stable text form: the ledger service checks attestations over exactly these bytes. */
    public byte[] canonicalBytes() {
        StringBuilder out =
                new StringBuilder()
                        .append(businessDate)
                        .append('\n')
                        .append(batchCount)
                        .append('\n');
        new TreeMap<>(totalsMinorUnits)
                .forEach(
                        (currency, total) ->
                                out.append(currency).append('=').append(total).append('\n'));
        return out.toString().getBytes(StandardCharsets.UTF_8);
    }
}
