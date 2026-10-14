package com.tallowbrook.driver.lockers

import android.os.Build
import java.security.PublicKey
import java.security.Signature

/**
 * Locker banks broadcast which compartments are free. A broadcast is only trusted if the bank's
 * signature verifies; older phones ignore broadcasts and ask the depot server instead.
 */
class LockerAnnouncements(private val bankKey: PublicKey) {

    data class Availability(val bankId: String, val freeSmall: Int, val freeLarge: Int)

    fun verify(announcement: ByteArray, signature: ByteArray): Boolean {
        if (Build.VERSION.SDK_INT < 33) {
            return false
        }
        val verifier = Signature.getInstance("Ed25519")
        verifier.initVerify(bankKey)
        verifier.update(announcement)
        return verifier.verify(signature)
    }

    fun parse(announcement: ByteArray): Availability {
        val fields = announcement.decodeToString().split('|')
        require(fields.size == 3) { "Malformed availability broadcast" }
        return Availability(fields[0], fields[1].toInt(), fields[2].toInt())
    }
}
