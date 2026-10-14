package com.tallowbrook.driver.auth

import android.content.Context
import android.content.pm.PackageManager
import android.util.Base64
import java.security.MessageDigest

/**
 * The sign-in request carries a hash of the app's signing certificate, so the identity service can
 * tell our release build from a repackaged one.
 */
object AppAttestation {

    fun signerHash(context: Context): String {
        val info =
            context.packageManager.getPackageInfo(
                context.packageName,
                PackageManager.GET_SIGNING_CERTIFICATES,
            )
        val signer =
            info.signingInfo?.apkContentsSigners?.firstOrNull() ?: error("Package has no signer")
        val digest = MessageDigest.getInstance("SHA-256").digest(signer.toByteArray())
        return Base64.encodeToString(digest, Base64.NO_WRAP)
    }
}
