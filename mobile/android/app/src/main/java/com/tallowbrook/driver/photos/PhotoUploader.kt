package com.tallowbrook.driver.photos

import android.util.Base64
import java.security.MessageDigest
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody

/**
 * Uploads proof-of-delivery photos to the pre-signed storage URLs the API hands out. The storage
 * service rejects a body whose Content-MD5 does not match, which catches truncated uploads.
 */
class PhotoUploader(private val http: OkHttpClient) {

    fun upload(signedUrl: String, photo: ByteArray) {
        val md = MessageDigest.getInstance("MD5")
        val contentHash = Base64.encodeToString(md.digest(photo), Base64.NO_WRAP)
        val request =
            Request.Builder()
                .url(signedUrl)
                .header("Content-MD5", contentHash)
                .put(photo.toRequestBody(JPEG))
                .build()
        http.newCall(request).execute().use { response ->
            check(response.isSuccessful) { "Photo upload failed with HTTP ${response.code}" }
        }
    }

    companion object {
        private val JPEG = "image/jpeg".toMediaType()
    }
}
