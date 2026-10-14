package com.tallowbrook.driver.data

import org.json.JSONObject

/** Today's route as sent by dispatch; parsed only after the manifest signature has been checked. */
data class RouteManifest(val routeId: String, val vehicle: VehicleType, val stops: List<Stop>) {

    fun markScanned(parcelId: String): RouteManifest {
        val index = stops.indexOfFirst { parcelId in it.parcelIds && !it.done }
        if (index < 0) return this
        return copy(
            stops = stops.mapIndexed { i, stop -> if (i == index) stop.copy(done = true) else stop }
        )
    }

    companion object {
        fun parse(json: String): RouteManifest {
            val root = JSONObject(json)
            val stops = root.getJSONArray("stops")
            val parsed =
                (0 until stops.length()).map { i ->
                    val s = stops.getJSONObject(i)
                    val parcels = s.getJSONArray("parcels")
                    Stop(
                        stopId = s.getString("id"),
                        addressLine = s.getString("address"),
                        latitude = s.getDouble("lat"),
                        longitude = s.getDouble("lon"),
                        parcelIds = (0 until parcels.length()).map(parcels::getString),
                        needsSignature = s.optBoolean("signature", false),
                    )
                }
            val vehicle =
                VehicleType.fromCode(root.getString("vehicle")) ?: error("Unknown vehicle type")
            return RouteManifest(root.getString("route"), vehicle, parsed)
        }
    }
}
