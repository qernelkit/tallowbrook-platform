package com.tallowbrook.driver.net

import android.util.Log
import java.util.concurrent.TimeUnit
import javax.net.ssl.SSLPeerUnverifiedException
import okhttp3.CertificatePinner
import okhttp3.ConnectionSpec
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody

/** Client for api.tallowbrook.example: pinned to our service key and its issuing CA. */
class ApiClient(private val baseUrl: String = "https://api.tallowbrook.example/") {

    val http: OkHttpClient =
        OkHttpClient.Builder()
            .certificatePinner(
                CertificatePinner.Builder().add(API_HOST, PIN_API, PIN_ISSUING_E2).build()
            )
            .connectionSpecs(listOf(ConnectionSpec.RESTRICTED_TLS))
            .connectTimeout(10, TimeUnit.SECONDS)
            .readTimeout(30, TimeUnit.SECONDS)
            .build()

    fun get(path: String): String = execute(Request.Builder().url(baseUrl + path).get().build())

    fun postJson(path: String, json: String): String =
        execute(Request.Builder().url(baseUrl + path).post(json.toRequestBody(JSON)).build())

    private fun execute(request: Request): String {
        try {
            http.newCall(request).execute().use { response ->
                if (!response.isSuccessful) {
                    throw ApiException(response.code, request.url.encodedPath)
                }
                return response.body.string()
            }
        } catch (e: SSLPeerUnverifiedException) {
            reportPinFailure(API_HOST, e)
            throw e
        }
    }

    class ApiException(val status: Int, path: String) : RuntimeException("HTTP $status from $path")

    companion object {
        private const val TAG = "ApiClient"
        private const val API_HOST = "api.tallowbrook.example"
        private val JSON = "application/json; charset=utf-8".toMediaType()
        private const val PIN_API = "sha256/48v3T31ykkEXFqIrdJsHGP68zELJJxF7dUnMG9C9HQE="
        private const val PIN_ISSUING_E2 = "sha256/4kV6UdjvNuNQhyP4aZmVCfbojXgD6WM8r2zF7O6m0/s="

        fun reportPinFailure(host: String, error: SSLPeerUnverifiedException) {
            Log.w(TAG, "Pinned certificate check failed for $host")
            Log.d(TAG, error.message ?: "no detail")
        }
    }
}
