package com.tallowbrook.driver.scan

/** GS1 SSCC-18 parcel labels, with or without the (00) application identifier in front. */
data class ParcelBarcode(val sscc: String) {

    val extensionDigit: Char
        get() = sscc[0]

    val companyAndSerial: String
        get() = sscc.substring(1, 17)

    companion object {
        fun parse(raw: String): ParcelBarcode? {
            val digits =
                raw.trim().removePrefix("(00)").let {
                    if (it.length == 20 && it.startsWith("00")) it.substring(2) else it
                }
            if (digits.length != 18 || !digits.all(Char::isDigit)) return null
            var weightedSum = 0
            for (i in 0 until 17) {
                val weight = if (i % 2 == 0) 3 else 1
                weightedSum += (digits[i] - '0') * weight
            }
            val checkDigit = (10 - weightedSum % 10) % 10
            return if (checkDigit == digits[17] - '0') ParcelBarcode(digits) else null
        }
    }
}
