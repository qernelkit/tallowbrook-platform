import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:pointycastle/export.dart';

/// The key for the offline scan queue, derived from the signed-in staff member's PIN
/// and the handheld's salt (provisioned at enrollment). A handheld left in a van does
/// not give up its queued scans without the PIN.
class QueueKey {
  static SecretKey derive({
    required String pin,
    required Uint8List deviceSalt,
  }) {
    final derivator = PBKDF2KeyDerivator(HMac(SHA256Digest(), 64))
      ..init(Pbkdf2Parameters(deviceSalt, 100000, 32));
    final bytes = derivator.process(Uint8List.fromList(utf8.encode(pin)));
    return SecretKey(bytes);
  }
}
