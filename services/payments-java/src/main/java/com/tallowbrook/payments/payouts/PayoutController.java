package com.tallowbrook.payments.payouts;

import com.tallowbrook.payments.support.ShortReferences;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Positive;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/v1/payout-runs")
public class PayoutController {

    public record CreateRun(
            @Positive long runNumber,
            @NotEmpty List<DeliveryEarnings> earnings,
            @NotEmpty Map<String, String> ibanByDriver) {}

    public record RunLine(String driverId, long amountMinor, String currency, String valueDate) {}

    private final DriverPayoutService payouts;
    private final PayoutLineRepository lines;
    private final ShortReferences references;

    public PayoutController(
            DriverPayoutService payouts, PayoutLineRepository lines, ShortReferences references) {
        this.payouts = payouts;
        this.lines = lines;
        this.references = references;
    }

    @PostMapping
    public Map<String, String> create(@Valid @RequestBody CreateRun request) {
        return Map.of(
                "run",
                payouts.createRun(request.runNumber(), request.earnings(), request.ibanByDriver()));
    }

    @GetMapping("/{run}")
    public List<RunLine> lines(@PathVariable String run) {
        references.payoutRun(run);
        return lines.findByRunIdOrderByDriverIdAsc(run).stream()
                .map(
                        l ->
                                new RunLine(
                                        l.getDriverId(),
                                        l.getAmountMinor(),
                                        l.getCurrency(),
                                        l.getValueDate().toString()))
                .toList();
    }
}
