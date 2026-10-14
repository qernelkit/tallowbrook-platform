package com.tallowbrook.driver.security

import android.app.Activity
import android.hardware.biometrics.BiometricPrompt
import android.os.CancellationSignal
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature

/**
 * Starting a shift needs the driver's fingerprint or face: the dispatch server sends a challenge,
 * and only a biometric unlock lets the device key answer it.
 */
class ShiftUnlock {

    fun ensureKey() {
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        if (store.containsAlias(ALIAS)) return
        val spec =
            KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_SIGN)
                .setKeySize(2048)
                .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PSS)
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setUserAuthenticationRequired(true)
                .setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
                .build()
        val generator =
            KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore")
        generator.initialize(spec)
        generator.generateKeyPair()
        Log.i(TAG, "Shift key ready (RSA-PSS, biometric)")
    }

    fun unlock(
        activity: Activity,
        challenge: ByteArray,
        onAnswered: (ByteArray) -> Unit,
        onFailed: (String) -> Unit,
    ) {
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val signature = Signature.getInstance(SHIFT_SIGNATURE)
        signature.initSign(store.getKey(ALIAS, null) as PrivateKey)
        val prompt =
            BiometricPrompt.Builder(activity)
                .setTitle("Start shift")
                .setSubtitle("Confirm it's you")
                .setNegativeButton("Cancel", activity.mainExecutor) { _, _ ->
                    onFailed("cancelled")
                }
                .build()
        prompt.authenticate(
            BiometricPrompt.CryptoObject(signature),
            CancellationSignal(),
            activity.mainExecutor,
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(
                    result: BiometricPrompt.AuthenticationResult
                ) {
                    val unlocked =
                        result.cryptoObject.signature ?: return onFailed("no key after unlock")
                    unlocked.update(challenge)
                    onAnswered(unlocked.sign())
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    onFailed(errString.toString())
                }
            },
        )
    }

    companion object {
        private const val TAG = "ShiftUnlock"
        private const val ALIAS = "shift-unlock"
        private const val SHIFT_SIGNATURE = "SHA256withRSA/PSS"
    }
}
