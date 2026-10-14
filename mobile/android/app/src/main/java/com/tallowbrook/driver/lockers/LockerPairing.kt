package com.tallowbrook.driver.lockers

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.KeyAgreement

/**
 * Bonding with a depot smart-locker bank over BLE: the phone and the locker bank exchange public
 * keys, and the agreed secret seeds the [LockerChannel]. The phone's half stays in Keystore.
 */
class LockerPairing(lockerBankId: String) {

    private val alias = "locker-$lockerBankId"

    /** Encoded public key to send to the locker bank in the bond request. */
    fun bondRequestKey(): ByteArray {
        val spec =
            KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_AGREE_KEY)
                .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                .build()
        val generator =
            KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
        generator.initialize(spec)
        return generator.generateKeyPair().public.encoded
    }

    fun agree(lockerBankKey: ByteArray): ByteArray {
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val ours = store.getKey(alias, null) as PrivateKey
        val theirs = KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(lockerBankKey))
        val agreement = KeyAgreement.getInstance("ECDH", "AndroidKeyStore")
        agreement.init(ours)
        agreement.doPhase(theirs, true)
        return agreement.generateSecret()
    }

    fun forget() {
        KeyStore.getInstance("AndroidKeyStore").apply { load(null) }.deleteEntry(alias)
    }
}
