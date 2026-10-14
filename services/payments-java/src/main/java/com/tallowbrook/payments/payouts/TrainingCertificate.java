package com.tallowbrook.payments.payouts;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.LocalDate;

/**
 * A contract driver's dangerous-goods training record. Drivers who carry hazmat parcels are only
 * paid the hazmat rate while their training is current.
 */
@Entity
@Table(name = "driver_training")
public class TrainingCertificate {

    @Id @GeneratedValue private Long id;

    @Column(name = "driver_id", nullable = false, length = 32)
    private String driverId;

    @Column(name = "course_code", nullable = false, length = 16)
    private String courseCode;

    @Column(name = "certificate_number", nullable = false)
    private String referenceNumber;

    @Column(name = "provider", nullable = false, length = 120)
    private String provider;

    @Column(name = "valid_until", nullable = false)
    private LocalDate validUntil;

    protected TrainingCertificate() {}

    public TrainingCertificate(
            String driverId,
            String courseCode,
            String referenceNumber,
            String provider,
            LocalDate validUntil) {
        this.driverId = driverId;
        this.courseCode = courseCode;
        this.referenceNumber = referenceNumber;
        this.provider = provider;
        this.validUntil = validUntil;
    }

    public String getDriverId() {
        return driverId;
    }

    public String getCourseCode() {
        return courseCode;
    }

    public String getReferenceNumber() {
        return referenceNumber;
    }

    public String getProvider() {
        return provider;
    }

    public LocalDate getValidUntil() {
        return validUntil;
    }

    public boolean validOn(LocalDate day) {
        return !validUntil.isBefore(day);
    }
}
