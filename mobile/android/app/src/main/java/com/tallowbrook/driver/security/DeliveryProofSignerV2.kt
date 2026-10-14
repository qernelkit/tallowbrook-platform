package com.tallowbrook.driver.security

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature

/**
 * Second proof-of-delivery signer for the newest company devices (Android 17 and later), whose
 * Keystore can hold lattice-based signing keys. Older devices keep using [DeliveryProofSigner].
 */
class DeliveryProofSignerV2(private val alias: String = "delivery-proof-v2") {

    fun isSupported(): Boolean = Build.VERSION.SDK_INT >= 37

    fun ensureKey() {
        if (Build.VERSION.SDK_INT >= 37) {
            val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            if (store.containsAlias(alias)) return
            val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN).build()
            val generator = KeyPairGenerator.getInstance("ML-DSA-65", "AndroidKeyStore")
            generator.initialize(spec)
            generator.generateKeyPair()
        }
    }

    fun sign(proof: DeliveryProof): ByteArray {
        check(isSupported()) { "Signer v2 needs Android 17" }
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val signer = Signature.getInstance("ML-DSA")
        signer.initSign(store.getKey(alias, null) as PrivateKey)
        signer.update(proof.canonicalBytes())
        return signer.sign()
    }
}
