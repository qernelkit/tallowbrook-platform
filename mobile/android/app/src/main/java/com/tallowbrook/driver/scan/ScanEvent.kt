package com.tallowbrook.driver.scan

/** One barcode read by a paired ring scanner: `<epoch millis>;<symbology>;<data>`. */
data class ScanEvent(
    val scannerId: String,
    val atMillis: Long,
    val symbology: String,
    val data: String,
) {
    companion object {
        fun parse(scannerId: String, text: String): ScanEvent {
            val parts = text.split(';', limit = 3)
            require(parts.size == 3) { "Malformed scan frame" }
            return ScanEvent(scannerId, parts[0].toLong(), parts[1], parts[2])
        }
    }
}
