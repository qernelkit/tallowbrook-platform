package com.tallowbrook.driver.security

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.spec.ECGenParameterSpec

/**
 * Signs proof-of-delivery records with a device key that never leaves the secure hardware. Company
 * devices all have StrongBox; the dispatch service checks the signature against the key registered
 * when the device was enrolled.
 */
class DeliveryProofSigner(private val alias: String = "delivery-proof") {

    private val sent = mutableSetOf<Int>()

    fun ensureKey() {
        val store = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        if (store.containsAlias(alias)) return
        val spec =
            KeyGenParameterSpec.Builder(
                    alias,
                    KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY,
                )
                .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setIsStrongBoxBacked(true)
                .build()
        val generator =
            KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE)
        generator.initialize(spec)
        generator.generateKeyPair()
        Log.i(TAG, "Delivery proof key created")
    }

    /** Returns null when this proof was already signed and queued during this shift. */
    fun sign(proof: DeliveryProof): ByteArray? {
        val dedupeKey = proof.hashCode()
        if (!sent.add(dedupeKey)) return null
        val signer = Signature.getInstance(SigningAlgorithms.ECDSA_P256_SHA256)
        val store = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        signer.initSign(store.getKey(alias, null) as PrivateKey)
        signer.update(proof.canonicalBytes())
        return signer.sign()
    }

    companion object {
        private const val TAG = "DeliveryProofSigner"
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    }
}
