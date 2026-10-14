package com.tallowbrook.driver.lockers

import com.google.crypto.tink.subtle.Hkdf
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Messages to and from a bonded locker bank (open door, door closed, parcel placed). Each frame is
 * `nonce || sealed message`; the session key comes from the bond secret and the bank's salt.
 */
class LockerChannel(agreedSecret: ByteArray, bankSalt: ByteArray) {

    private val key: SecretKeySpec

    init {
        val sessionKey = Hkdf.computeHkdf("HMACSHA256", agreedSecret, bankSalt, LOCKER_INFO, 32)
        key = SecretKeySpec(sessionKey, "ChaCha20")
    }

    fun seal(message: ByteArray): ByteArray {
        val nonce = ByteArray(NONCE_BYTES).also { random.nextBytes(it) }
        return nonce + cipher(Cipher.ENCRYPT_MODE, nonce).doFinal(message)
    }

    fun open(frame: ByteArray): ByteArray {
        require(frame.size > NONCE_BYTES + 16) { "Frame too short" }
        val nonce = frame.copyOfRange(0, NONCE_BYTES)
        return cipher(Cipher.DECRYPT_MODE, nonce)
            .doFinal(frame, NONCE_BYTES, frame.size - NONCE_BYTES)
    }

    private fun cipher(mode: Int, nonce: ByteArray): Cipher {
        val cipher = Cipher.getInstance("ChaCha20/Poly1305/NoPadding")
        cipher.init(mode, key, IvParameterSpec(nonce))
        return cipher
    }

    companion object {
        private const val NONCE_BYTES = 12
        private val LOCKER_INFO = "tallowbrook-locker/v1".toByteArray()
        private val random = SecureRandom()
    }
}
