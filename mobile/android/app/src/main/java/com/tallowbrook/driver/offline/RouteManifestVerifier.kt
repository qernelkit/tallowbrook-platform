package com.tallowbrook.driver.offline

import android.util.Base64
import com.tallowbrook.driver.security.SigningAlgorithms
import java.security.KeyFactory
import java.security.PublicKey
import java.security.Signature
import java.security.spec.X509EncodedKeySpec

/**
 * Route manifests are signed by the dispatch service; the app refuses a manifest that does not
 * verify.
 */
object RouteManifestVerifier {

    private val ROUTE_KEY_PEM =
        """
            -----BEGIN PUBLIC KEY-----
            MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEQKomyBVpBNpmoaISQ8Cu2ZbQRyv5
            dRaF1lQZvjYI6/jb0HlcAO1n5Zp1VchZMKdzA3GYtzjiuKersi0RmnY6Uw==
            -----END PUBLIC KEY-----
        """
            .trimIndent()

    private val dispatchKey: PublicKey by lazy {
        val body =
            ROUTE_KEY_PEM.lineSequence().filterNot { it.startsWith("-----") }.joinToString("")
        KeyFactory.getInstance("EC")
            .generatePublic(X509EncodedKeySpec(Base64.decode(body, Base64.DEFAULT)))
    }

    fun verify(manifest: ByteArray, signature: ByteArray): Boolean {
        if (signature.isEmpty()) return false
        val verifier = Signature.getInstance(SigningAlgorithms.ECDSA_P256_SHA256)
        verifier.initVerify(dispatchKey)
        verifier.update(manifest)
        return verifier.verify(signature)
    }
}
