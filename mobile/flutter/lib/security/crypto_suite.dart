// Algorithm choices shared across the scanner app. Change them here, and bump the
// queue format version in scan_queue_store.dart when the queue cipher changes.
import 'package:cryptography/cryptography.dart';

/// Offline scan queue entries.
final queueCipher = AesGcm.with256bits();

/// Staff PIN verifier, tuned so a check takes about a quarter of a second on the
/// oldest handhelds still in service.
final pinHasher = Argon2id(
  parallelism: 1,
  memory: 19456,
  iterations: 2,
  hashLength: 32,
);

/// Print jobs sent to paired Bluetooth label printers.
final printerChannelCipher = Chacha20.poly1305Aead();

/// Session keys for printer pairing.
final printerKdf = Hkdf(hmac: Hmac.sha256(), outputLength: 32);
