package com.tallowbrook.payments.support;

import com.tallowbrook.payments.config.PaymentsProperties;

import org.hashids.Hashids;
import org.springframework.stereotype.Component;

/** Short payout references that drivers can read out over the phone. */
@Component
public class ShortReferences {

    private final Hashids hashids;

    public ShortReferences(PaymentsProperties properties) {
        this.hashids = new Hashids(properties.referenceSalt(), 8);
    }

    public String payoutReference(long payoutRun) {
        return hashids.encode(payoutRun);
    }

    public long payoutRun(String reference) {
        long[] decoded = hashids.decode(reference);
        if (decoded.length != 1) {
            throw new IllegalArgumentException("Not a payout reference: " + reference);
        }
        return decoded[0];
    }
}
