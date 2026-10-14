package com.tallowbrook.driver.telematics

import org.json.JSONArray
import org.json.JSONObject

/** GPS and speed samples collected between two uploads. */
data class TelematicsSample(
    val atMillis: Long,
    val latitude: Double,
    val longitude: Double,
    val speedKmh: Float,
)

class TelematicsBatch(val vehicleId: String, private val maxSamples: Int = 600) {
    private val samples = ArrayList<TelematicsSample>()

    val isFull: Boolean
        get() = samples.size >= maxSamples

    fun add(sample: TelematicsSample) {
        if (samples.isNotEmpty() && sample.atMillis < samples.last().atMillis) return
        samples += sample
    }

    fun toJson(): String {
        val points = JSONArray()
        for (s in samples) {
            points.put(
                JSONObject()
                    .put("t", s.atMillis)
                    .put("lat", s.latitude)
                    .put("lon", s.longitude)
                    .put("v", s.speedKmh.toDouble())
            )
        }
        return JSONObject().put("vehicle", vehicleId).put("points", points).toString()
    }

    fun clear() = samples.clear()
}
