package com.tallowbrook.payments.payouts;

import java.time.LocalDate;

/** What a driver earned on one route day, as reported by the dispatch service. */
public record DeliveryEarnings(
        String driverId,
        LocalDate routeDate,
        int stops,
        int hazmatStops,
        long baseMinor,
        String currency) {

    public DeliveryEarnings {
        if (stops < 0 || hazmatStops < 0 || hazmatStops > stops) {
            throw new IllegalArgumentException("Inconsistent stop counts for " + driverId);
        }
    }
}
