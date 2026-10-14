package com.tallowbrook.driver.data

data class Stop(
    val stopId: String,
    val addressLine: String,
    val latitude: Double,
    val longitude: Double,
    val parcelIds: List<String>,
    val needsSignature: Boolean,
    val done: Boolean = false,
)
