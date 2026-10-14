package com.tallowbrook.driver.net

import java.util.concurrent.TimeUnit
import okhttp3.CipherSuite
import okhttp3.ConnectionSpec
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.TlsVersion

/** Talks to the depot's local server on the warehouse Wi-Fi when the vans are loading. */
class DepotLocalClient(private val depotHost: String) {

    private val spec =
        ConnectionSpec.Builder(ConnectionSpec.MODERN_TLS)
            .tlsVersions(TlsVersion.TLS_1_3)
            .cipherSuites(
                CipherSuite.TLS_AES_256_GCM_SHA384,
                CipherSuite.TLS_CHACHA20_POLY1305_SHA256,
            )
            .build()

    val http: OkHttpClient =
        OkHttpClient.Builder()
            .connectionSpecs(listOf(spec))
            .connectTimeout(5, TimeUnit.SECONDS)
            .readTimeout(15, TimeUnit.SECONDS)
            .build()

    fun loadingPlan(routeId: String): String {
        val request = Request.Builder().url("https://$depotHost/loading/$routeId").build()
        http.newCall(request).execute().use { response ->
            check(response.isSuccessful) { "Depot server answered ${response.code}" }
            return response.body.string()
        }
    }
}
