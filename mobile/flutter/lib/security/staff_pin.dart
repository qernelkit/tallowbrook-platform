import 'dart:convert';
import 'dart:math';

import 'crypto_suite.dart';

/// A stored PIN verifier: the salt and the derived hash, base64 in the device profile.
class PinVerifier {
  PinVerifier({required this.salt, required this.hash});

  factory PinVerifier.fromJson(Map<String, Object?> json) => PinVerifier(
    salt: base64.decode(json['salt']! as String),
    hash: base64.decode(json['hash']! as String),
  );

  final List<int> salt;
  final List<int> hash;

  Map<String, Object?> toJson() => {
    'salt': base64.encode(salt),
    'hash': base64.encode(hash),
  };
}

/// Staff sign in to a handheld with a 6-digit PIN. The depot server provisions the
/// verifier; the handheld checks PINs offline against it.
class StaffPin {
  static const length = 6;
  static const maxAttempts = 5;

  int _failedAttempts = 0;

  bool get lockedOut => _failedAttempts >= maxAttempts;

  static bool isWellFormed(String pin) =>
      pin.length == length &&
      pin.codeUnits.every((c) => c >= 0x30 && c <= 0x39);

  /// Creates a verifier for a new PIN (used when a supervisor resets one on the device).
  static Future<PinVerifier> enroll(String pin) async {
    final random = Random.secure();
    final salt = List<int>.generate(16, (_) => random.nextInt(256));
    return PinVerifier(salt: salt, hash: await _hash(pin, salt));
  }

  Future<bool> check(String pin, PinVerifier verifier) async {
    if (lockedOut || !isWellFormed(pin)) {
      return false;
    }
    final candidate = await _hash(pin, verifier.salt);
    final ok = _constantTimeEquals(candidate, verifier.hash);
    _failedAttempts = ok ? 0 : _failedAttempts + 1;
    return ok;
  }

  void resetAttempts() => _failedAttempts = 0;

  static Future<List<int>> _hash(String pin, List<int> salt) async {
    final key = await pinHasher.deriveKeyFromPassword(
      password: pin,
      nonce: salt,
    );
    return key.extractBytes();
  }

  static bool _constantTimeEquals(List<int> a, List<int> b) {
    if (a.length != b.length) {
      return false;
    }
    var diff = 0;
    for (var i = 0; i < a.length; i++) {
      diff |= a[i] ^ b[i];
    }
    return diff == 0;
  }
}
