package com.tallowbrook.driver.util

import android.util.Base64

/** Small helpers for showing and passing data around in the UI layer. */
object CryptoUtils {
    fun toBase64(bytes: ByteArray): String = Base64.encodeToString(bytes, Base64.NO_WRAP)

    fun fromBase64(text: String): ByteArray = Base64.decode(text, Base64.NO_WRAP)

    fun encryptForDisplay(phone: String): String = phone.take(3) + "•••" + phone.takeLast(2)
}
