package com.tallowbrook.driver.net

import android.util.Log
import java.security.Security
import org.conscrypt.Conscrypt

/** Puts Conscrypt in front of the platform provider so every device gets the same TLS stack. */
object TlsProvider {
    private const val TAG = "TlsProvider"

    @Volatile private var installed = false

    @Synchronized
    fun install() {
        if (installed) return
        Security.insertProviderAt(Conscrypt.newProvider(), 1)
        installed = true
        Log.i(TAG, "Provider installed at position 1")
    }
}
