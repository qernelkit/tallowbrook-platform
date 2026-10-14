package com.tallowbrook.driver.auth

import android.util.Base64
import java.security.MessageDigest
import java.security.SecureRandom

/** Proof key for the driver sign-in flow (RFC 7636). */
object PkceChallenge {
    private const val CODE_CHALLENGE_DIGEST = "SHA-256"
    const val CHALLENGE_METHOD = "S256"

    fun newVerifier(): String {
        val bytes = ByteArray(32).also { SecureRandom().nextBytes(it) }
        return Base64.encodeToString(bytes, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)
    }

    fun challengeFor(verifier: String): String {
        val digest =
            MessageDigest.getInstance(CODE_CHALLENGE_DIGEST)
                .digest(verifier.toByteArray(Charsets.US_ASCII))
        return Base64.encodeToString(digest, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)
    }
}
