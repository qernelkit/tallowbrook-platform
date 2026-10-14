package com.tallowbrook.payments.archive;

/**
 * An archive key and the encapsulation stored beside the archive. Escrow officers holding the
 * escrow private key can recover the archive key from the encapsulation alone.
 */
public record EscrowedArchiveKey(byte[] secret, byte[] encapsulation) {}
