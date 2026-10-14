package com.tallowbrook.payments.merchant;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;

@RestController
@RequestMapping("/v1/merchants")
public class MerchantController {

    public record CreateMerchant(
            @NotBlank @Size(max = 200) String legalName,
            @Pattern(regexp = "[A-Z]{2}") String country,
            @Pattern(regexp = "[A-Z]{3}") String settlementCurrency) {}

    public record MerchantView(
            String reference,
            String legalName,
            String country,
            String settlementCurrency,
            String status) {}

    private final MerchantRepository merchants;
    private final MerchantRefObfuscator references;

    public MerchantController(MerchantRepository merchants, MerchantRefObfuscator references) {
        this.merchants = merchants;
        this.references = references;
    }

    @PostMapping
    @Transactional
    public ResponseEntity<MerchantView> create(@Valid @RequestBody CreateMerchant request) {
        long id = merchants.count() + 100_001L;
        Merchant merchant =
                merchants.save(
                        new Merchant(
                                id,
                                request.legalName(),
                                request.country(),
                                request.settlementCurrency()));
        return ResponseEntity.status(HttpStatus.CREATED).body(view(merchant));
    }

    @GetMapping("/{reference}")
    public MerchantView get(@PathVariable String reference) {
        long id = references.fromPublicRef(reference);
        return merchants
                .findById(id)
                .map(this::view)
                .orElseThrow(
                        () ->
                                new ResponseStatusException(
                                        HttpStatus.NOT_FOUND, "No such merchant"));
    }

    @GetMapping
    public List<MerchantView> byCountry(
            @RequestParam @Pattern(regexp = "[A-Z]{2}") String country) {
        return merchants.findByCountryOrderByLegalNameAsc(country).stream()
                .map(this::view)
                .toList();
    }

    @PostMapping("/{reference}/suspend")
    @Transactional
    public MerchantView suspend(@PathVariable String reference) {
        Merchant merchant =
                merchants
                        .findById(references.fromPublicRef(reference))
                        .orElseThrow(
                                () ->
                                        new ResponseStatusException(
                                                HttpStatus.NOT_FOUND, "No such merchant"));
        merchant.suspend();
        return view(merchant);
    }

    private MerchantView view(Merchant merchant) {
        return new MerchantView(
                references.toPublicRef(merchant.getId()),
                merchant.getLegalName(),
                merchant.getCountry(),
                merchant.getSettlementCurrency(),
                merchant.getStatus().name());
    }
}
