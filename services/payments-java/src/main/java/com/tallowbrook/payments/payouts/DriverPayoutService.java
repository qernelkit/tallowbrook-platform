package com.tallowbrook.payments.payouts;

import com.tallowbrook.payments.support.ShortReferences;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Builds the weekly payout run for contract drivers. Hazmat stops pay a supplement, but only when
 * the driver's dangerous-goods training is current on the route day.
 */
@Service
public class DriverPayoutService {

    private static final Logger log = LoggerFactory.getLogger(DriverPayoutService.class);
    private static final String HAZMAT_COURSE = "ADR-BASIC";
    private static final long HAZMAT_SUPPLEMENT_MINOR = 250;

    private final DriverTrainingRepository training;
    private final PayoutLineRepository lines;
    private final ShortReferences references;
    private final Clock clock;

    public DriverPayoutService(
            DriverTrainingRepository training,
            PayoutLineRepository lines,
            ShortReferences references) {
        this.training = training;
        this.lines = lines;
        this.references = references;
        this.clock = Clock.systemUTC();
    }

    @Transactional
    public String createRun(
            long runNumber, List<DeliveryEarnings> earnings, Map<String, String> ibanByDriver) {
        String runId = references.payoutReference(runNumber);
        LocalDate valueDate = nextBusinessDay(LocalDate.now(clock));
        List<PayoutLine> created = new ArrayList<>();
        for (DeliveryEarnings day : earnings) {
            String iban = ibanByDriver.get(day.driverId());
            if (iban == null) {
                log.warn("Driver {} has no payout account; skipped", day.driverId());
                continue;
            }
            long amount = day.baseMinor();
            if (day.hazmatStops() > 0 && hazmatTrainingCurrent(day.driverId(), day.routeDate())) {
                amount += day.hazmatStops() * HAZMAT_SUPPLEMENT_MINOR;
            }
            String text = "Route " + day.routeDate() + ", " + day.stops() + " stops";
            created.add(
                    new PayoutLine(
                            runId, day.driverId(), iban, amount, day.currency(), valueDate, text));
        }
        lines.saveAll(created);
        log.info("Payout run {} with {} lines, value date {}", runId, created.size(), valueDate);
        return runId;
    }

    private boolean hazmatTrainingCurrent(String driverId, LocalDate routeDate) {
        return training.findByDriverIdAndCourseCode(driverId, HAZMAT_COURSE).stream()
                .anyMatch(record -> record.validOn(routeDate));
    }

    static LocalDate nextBusinessDay(LocalDate from) {
        LocalDate day = from.plusDays(1);
        while (day.getDayOfWeek().getValue() >= 6) {
            day = day.plusDays(1);
        }
        return day;
    }
}
