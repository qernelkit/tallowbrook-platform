package com.tallowbrook.driver.storage

import android.content.Context
import com.google.crypto.tink.Aead
import com.google.crypto.tink.KeyTemplates
import com.google.crypto.tink.RegistryConfiguration
import com.google.crypto.tink.aead.AeadConfig
import com.google.crypto.tink.integration.android.AndroidKeysetManager

/** The keyset that protects the downloaded route manifest on disk, itself wrapped by Keystore. */
object ManifestKeyset {
    private const val KEYSET_NAME = "route_manifest_keyset"
    private const val PREFS_NAME = "route_manifest_prefs"
    private const val MASTER_KEY_URI = "android-keystore://route_manifest_master"

    @Volatile private var cached: Aead? = null

    @Synchronized
    fun aead(context: Context): Aead {
        cached?.let {
            return it
        }
        AeadConfig.register()
        val handle =
            AndroidKeysetManager.Builder()
                .withSharedPref(context, KEYSET_NAME, PREFS_NAME)
                .withKeyTemplate(KeyTemplates.get("AES256_GCM"))
                .withMasterKeyUri(MASTER_KEY_URI)
                .build()
                .keysetHandle
        return handle.getPrimitive(RegistryConfiguration.get(), Aead::class.java).also {
            cached = it
        }
    }
}
