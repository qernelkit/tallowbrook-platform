package com.tallowbrook.driver.telematics

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyStore
import java.security.MessageDigest
import javax.crypto.KeyGenerator
import javax.crypto.Mac
import javax.crypto.SecretKey

/**
 * Telematics batches wait on disk until the van has signal. Each batch gets a tag from a device key
 * when it is written, and the uploader drops any batch whose tag no longer matches.
 */
class TelematicsSigner {

    fun ensureKey() {
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        if (store.containsAlias(ALIAS)) return
        val spec =
            KeyGenParameterSpec.Builder(
                    ALIAS,
                    KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY,
                )
                .setIsStrongBoxBacked(true)
                .build()
        val generator =
            KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_HMAC_SHA256, "AndroidKeyStore")
        generator.init(spec)
        generator.generateKey()
    }

    fun tag(batch: ByteArray): String = Base64.encodeToString(mac().doFinal(batch), Base64.NO_WRAP)

    fun stillIntact(batch: ByteArray, tag: String): Boolean =
        MessageDigest.isEqual(mac().doFinal(batch), Base64.decode(tag, Base64.NO_WRAP))

    private fun mac(): Mac {
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val mac = Mac.getInstance(UPLOAD_MAC)
        mac.init(store.getKey(ALIAS, null) as SecretKey)
        return mac
    }

    companion object {
        private const val ALIAS = "telematics-batches"
        private const val UPLOAD_MAC = "HmacSHA256"
    }
}
