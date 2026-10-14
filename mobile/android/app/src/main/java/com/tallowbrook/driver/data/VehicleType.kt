package com.tallowbrook.driver.data

enum class VehicleType(val code: String) {
    VAN("VAN"),
    TRUCK_7T("T7"),
    CARGO_BIKE("BIKE");

    companion object {
        fun fromCode(code: String): VehicleType? = entries.firstOrNull { it.code == code }

        val fleetModels =
            mapOf(
                "SPR" to "Sprinter 3.5t",
                "FAL" to "Falcon 3.5t",
                "ATG" to "Atego 7.5t",
                "LCB" to "Load cargo bike",
            )
    }
}
