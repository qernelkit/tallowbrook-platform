package com.tallowbrook.driver.data

import java.time.LocalDate

/** Training records shown on the driver's profile and checked before hazmat routes are offered. */
data class HazmatCertificate(val course: String, val issuedBy: String, val expires: LocalDate) {
    fun isValidOn(day: LocalDate): Boolean = !expires.isBefore(day)
}

data class DrivingLicence(val number: String, val categories: Set<String>, val expires: LocalDate) {
    fun allows(vehicle: VehicleType): Boolean =
        when (vehicle) {
            VehicleType.CARGO_BIKE -> true
            VehicleType.VAN -> "B" in categories
            VehicleType.TRUCK_7T -> "C1" in categories
        }
}
