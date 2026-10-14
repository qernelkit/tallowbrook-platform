package com.tallowbrook.driver.storage

import java.io.File
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec

/**
 * Route and stop data cached for dead zones. Files are named after the route id and hold `iv ||
 * sealed bytes`; the key lives in Android Keystore.
 */
class OfflineCache(private val dir: File) {

    private fun newCipher(): Cipher = Cipher.getInstance("AES/GCM/NoPadding")

    fun write(routeId: String, plain: ByteArray) {
        val fileName = routeId.hashCode().toUInt().toString(16)
        val sealer = newCipher()
        sealer.init(Cipher.ENCRYPT_MODE, OfflineCacheKey.get())
        val sealed = sealer.doFinal(plain)
        dir.mkdirs()
        File(dir, "$fileName.bin")
            .writeBytes(byteArrayOf(sealer.iv.size.toByte()) + sealer.iv + sealed)
    }

    fun read(routeId: String): ByteArray? {
        val file = File(dir, "${routeId.hashCode().toUInt().toString(16)}.bin")
        if (!file.exists()) return null
        val stored = file.readBytes()
        val ivLength = stored[0].toInt()
        val iv = stored.copyOfRange(1, 1 + ivLength)
        val opener = newCipher()
        opener.init(Cipher.DECRYPT_MODE, OfflineCacheKey.get(), GCMParameterSpec(128, iv))
        return opener.doFinal(stored, 1 + ivLength, stored.size - 1 - ivLength)
    }

    fun evictOlderThan(maxAgeMillis: Long) {
        val cutoff = System.currentTimeMillis() - maxAgeMillis
        dir.listFiles()?.filter { it.lastModified() < cutoff }?.forEach { it.delete() }
    }
}
