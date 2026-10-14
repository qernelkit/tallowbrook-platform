package com.tallowbrook.driver.pairing

import android.util.Base64
import com.tallowbrook.driver.pairing.PairingProtocol.IV_LENGTH
import com.tallowbrook.driver.pairing.PairingProtocol.MAX_FRAME
import com.tallowbrook.driver.scan.ScanEvent
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * A ring scanner paired to this phone. The depot prints a link code on each scanner's charging
 * cradle; scanning it gives the phone the key the scanner uses for its scan frames.
 */
class ScannerPairing private constructor(val scannerId: String, private val linkKey: SecretKey) {

    fun decodeFrame(frame: ByteArray): ScanEvent {
        require(frame.size in (IV_LENGTH + 16)..MAX_FRAME) { "Unexpected frame size ${frame.size}" }
        val iv = frame.copyOfRange(0, IV_LENGTH)
        val cipher = Cipher.getInstance(PairingProtocol.PAYLOAD_CIPHER)
        cipher.init(Cipher.DECRYPT_MODE, linkKey, IvParameterSpec(iv))
        val clear = cipher.doFinal(frame, IV_LENGTH, frame.size - IV_LENGTH)
        return ScanEvent.parse(scannerId, clear.decodeToString())
    }

    companion object {
        /** Link code format: `<scanner id>:<base64 key>`. */
        fun fromLinkCode(code: String): ScannerPairing {
            val parts = code.trim().split(':', limit = 2)
            require(parts.size == 2) { "Not a scanner link code" }
            val raw = Base64.decode(parts[1], Base64.NO_WRAP)
            require(raw.size == 16) { "Link code has the wrong length" }
            return ScannerPairing(parts[0], SecretKeySpec(raw, "AES"))
        }
    }
}
