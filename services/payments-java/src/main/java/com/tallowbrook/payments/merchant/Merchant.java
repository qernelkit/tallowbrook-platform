package com.tallowbrook.payments.merchant;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.Instant;

@Entity
@Table(name = "merchants")
public class Merchant {

    public enum Status {
        ONBOARDING,
        ACTIVE,
        SUSPENDED,
        CLOSED
    }

    @Id private Long id;

    @Column(name = "legal_name", nullable = false, length = 200)
    private String legalName;

    @Column(name = "country", nullable = false, length = 2)
    private String country;

    @Column(name = "settlement_currency", nullable = false, length = 3)
    private String settlementCurrency;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 16)
    private Status status;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    protected Merchant() {}

    public Merchant(Long id, String legalName, String country, String settlementCurrency) {
        this.id = id;
        this.legalName = legalName;
        this.country = country;
        this.settlementCurrency = settlementCurrency;
        this.status = Status.ONBOARDING;
        this.createdAt = Instant.now();
    }

    public Long getId() {
        return id;
    }

    public String getLegalName() {
        return legalName;
    }

    public String getCountry() {
        return country;
    }

    public String getSettlementCurrency() {
        return settlementCurrency;
    }

    public Status getStatus() {
        return status;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public void activate() {
        if (status != Status.ONBOARDING && status != Status.SUSPENDED) {
            throw new IllegalStateException("Cannot activate a merchant in status " + status);
        }
        status = Status.ACTIVE;
    }

    public void suspend() {
        if (status == Status.CLOSED) {
            throw new IllegalStateException("Merchant is closed");
        }
        status = Status.SUSPENDED;
    }

    public void close() {
        status = Status.CLOSED;
    }
}
