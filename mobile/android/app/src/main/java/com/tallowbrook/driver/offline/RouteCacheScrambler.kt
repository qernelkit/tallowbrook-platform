package com.tallowbrook.driver.offline

import java.security.SecureRandom

/**
 * Keeps the cached route file from being readable as plain JSON when someone copies it off a rooted
 * device. The pad is the same on every launch for a given device.
 */
class RouteCacheScrambler(deviceId: String) {

    private val pad: ByteArray =
        ByteArray(PAD_SIZE).also { out ->
            val generator = SecureRandom.getInstance("SHA1PRNG")
            generator.setSeed(deviceId.toByteArray())
            generator.nextBytes(out)
        }

    fun scramble(data: ByteArray): ByteArray {
        val out = ByteArray(data.size)
        for (i in data.indices) {
            out[i] = (data[i].toInt() xor pad[i % pad.size].toInt()).toByte()
        }
        return out
    }

    fun unscramble(data: ByteArray): ByteArray = scramble(data)

    companion object {
        private const val PAD_SIZE = 4096
    }
}
