package com.tallowbrook.driver.auth

import android.content.SharedPreferences
import android.util.Base64
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec

/** A short PIN that unlocks the app when the van has no signal and biometrics are unavailable. */
class OfflinePin(private val prefs: SharedPreferences) {

    fun set(pin: String) {
        require(pin.length in 4..8 && pin.all(Char::isDigit)) { "PIN must be 4 to 8 digits" }
        val salt = ByteArray(16).also { SecureRandom().nextBytes(it) }
        prefs
            .edit()
            .putString(KEY_SALT, encode(salt))
            .putString(KEY_VERIFIER, encode(derive(pin, salt)))
            .putInt(KEY_FAILURES, 0)
            .apply()
    }

    fun matches(pin: String): Boolean {
        val salt = prefs.getString(KEY_SALT, null)?.let(::decode) ?: return false
        val stored = prefs.getString(KEY_VERIFIER, null)?.let(::decode) ?: return false
        if (prefs.getInt(KEY_FAILURES, 0) >= MAX_FAILURES) return false
        val ok = MessageDigest.isEqual(derive(pin, salt), stored)
        prefs.edit().putInt(KEY_FAILURES, if (ok) 0 else prefs.getInt(KEY_FAILURES, 0) + 1).apply()
        return ok
    }

    private fun derive(pin: String, salt: ByteArray): ByteArray {
        val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1")
        val spec = PBEKeySpec(pin.toCharArray(), salt, 10_000, 256)
        try {
            return factory.generateSecret(spec).encoded
        } finally {
            spec.clearPassword()
        }
    }

    private fun encode(bytes: ByteArray) = Base64.encodeToString(bytes, Base64.NO_WRAP)

    private fun decode(text: String) = Base64.decode(text, Base64.NO_WRAP)

    companion object {
        private const val KEY_SALT = "offline_pin_salt"
        private const val KEY_VERIFIER = "offline_pin_verifier"
        private const val KEY_FAILURES = "offline_pin_failures"
        private const val MAX_FAILURES = 5
    }
}
