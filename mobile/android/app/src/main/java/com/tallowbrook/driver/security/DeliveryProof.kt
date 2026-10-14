package com.tallowbrook.driver.security

import java.io.ByteArrayOutputStream
import java.io.DataOutputStream

/** What the driver captured at the door. The device signs [canonicalBytes]. */
class DeliveryProof(
    val parcelId: String,
    val stopId: String,
    val capturedAtMillis: Long,
    val latitude: Double,
    val longitude: Double,
    val photo: ByteArray,
    val drawnSignature: ByteArray,
) {
    fun canonicalBytes(): ByteArray {
        val out = ByteArrayOutputStream()
        DataOutputStream(out).use { data ->
            data.writeUTF(parcelId)
            data.writeUTF(stopId)
            data.writeLong(capturedAtMillis)
            data.writeDouble(latitude)
            data.writeDouble(longitude)
            data.writeInt(photo.size)
            data.write(photo)
            data.writeInt(drawnSignature.size)
            data.write(drawnSignature)
        }
        return out.toByteArray()
    }

    override fun equals(other: Any?): Boolean =
        other is DeliveryProof &&
            other.parcelId == parcelId &&
            other.capturedAtMillis == capturedAtMillis

    override fun hashCode(): Int = 31 * parcelId.hashCode() + capturedAtMillis.hashCode()
}
