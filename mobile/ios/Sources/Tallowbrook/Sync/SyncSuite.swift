import CryptoKit

/// Key encapsulation for device-to-device sync on systems that have it (iOS 26 and later).
/// Older devices agree keys with Curve25519 instead; see SyncKeyExchange.
@available(iOS 26.0, *) typealias SyncKEM = MLKEM1024
