package com.tallowbrook.driver.pairing

/** Constants of the ring-scanner link, from the scanner vendor's integration guide (rev. F). */
object PairingProtocol {
    const val SERVICE_UUID = "6e4f0001-b5a3-f393-e0a9-e50e24dcca9e"
    const val SCAN_CHARACTERISTIC = "6e4f0003-b5a3-f393-e0a9-e50e24dcca9e"
    const val PAYLOAD_CIPHER = "AES/CBC/PKCS7Padding"
    const val IV_LENGTH = 16
    const val MAX_FRAME = 244
}
