package com.tallowbrook.driver.storage

import com.google.crypto.tink.Aead
import com.google.crypto.tink.KeysetHandle
import com.google.crypto.tink.RegistryConfiguration
import com.google.crypto.tink.aead.AeadConfig
import com.google.crypto.tink.aead.AesGcmKeyManager
import java.io.File
import java.util.zip.CRC32

/**
 * Proof-of-delivery photos wait here until the upload queue drains. Photos are sealed with a
 * per-shift key held only in memory, so a lost phone does not leak the shift's photos.
 */
class PhotoVault(private val dir: File) {

    private var keyset: KeysetHandle? = null

    init {
        AeadConfig.register()
    }

    @Synchronized
    fun store(parcelId: String, photo: ByteArray): File {
        val crc = CRC32().apply { update(photo) }.value
        val handle =
            keyset
                ?: KeysetHandle.generateNew(AesGcmKeyManager.aes256GcmTemplate()).also {
                    keyset = it
                }
        val aead = handle.getPrimitive(RegistryConfiguration.get(), Aead::class.java)
        val sealed = aead.encrypt(photo, parcelId.toByteArray())
        dir.mkdirs()
        File(dir, "$parcelId.crc").writeText(crc.toString(16))
        return File(dir, "$parcelId.sealed").apply { writeBytes(sealed) }
    }

    /** Returns null when the photo is missing or did not read back whole. */
    @Synchronized
    fun load(parcelId: String): ByteArray? {
        val handle = keyset ?: return null
        val file = File(dir, "$parcelId.sealed")
        if (!file.exists()) return null
        val aead = handle.getPrimitive(RegistryConfiguration.get(), Aead::class.java)
        val photo = aead.decrypt(file.readBytes(), parcelId.toByteArray())
        val expected = File(dir, "$parcelId.crc").readText().toLong(16)
        return photo.takeIf { CRC32().apply { update(it) }.value == expected }
    }

    /** Called at the end of a shift once every photo has been uploaded. */
    @Synchronized
    fun endShift() {
        keyset = null
        dir.listFiles()?.forEach { it.delete() }
    }
}
