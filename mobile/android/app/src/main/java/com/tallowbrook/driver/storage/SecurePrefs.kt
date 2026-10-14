package com.tallowbrook.driver.storage

import android.content.Context
import android.content.SharedPreferences
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

/** Small secrets the app keeps between launches: the session token and the driver's depot. */
object SecurePrefs {
    private const val FILE = "driver_secure_prefs"
    private const val SESSION = "session_token"
    private const val DEPOT = "depot_code"

    @Volatile private var prefs: SharedPreferences? = null

    private fun open(context: Context): SharedPreferences {
        prefs?.let {
            return it
        }
        val masterKey =
            MasterKey.Builder(context)
                .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
                .setRequestStrongBoxBacked(true)
                .build()
        return EncryptedSharedPreferences.create(
                context,
                FILE,
                masterKey,
                EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
            )
            .also { prefs = it }
    }

    fun sessionToken(context: Context): String? = open(context).getString(SESSION, null)

    fun saveSession(context: Context, token: String, depotCode: String) {
        open(context).edit().putString(SESSION, token).putString(DEPOT, depotCode).apply()
    }

    fun depotCode(context: Context): String? = open(context).getString(DEPOT, null)

    fun clear(context: Context) {
        open(context).edit().clear().apply()
    }
}
