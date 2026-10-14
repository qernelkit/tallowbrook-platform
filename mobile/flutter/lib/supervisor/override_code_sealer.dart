import 'dart:convert';
import 'dart:typed_data';

import 'package:pointycastle/export.dart';

/// HQ's public key for override codes, fetched at sign-in as modulus and exponent.
class HqOverrideKey {
  HqOverrideKey({
    required this.keyId,
    required this.modulus,
    required this.exponent,
  });

  factory HqOverrideKey.fromJson(Map<String, Object?> json) => HqOverrideKey(
    keyId: json['kid']! as String,
    modulus: BigInt.parse(json['n_hex']! as String, radix: 16),
    exponent: BigInt.parse(json['e_hex']! as String, radix: 16),
  );

  final String keyId;
  final BigInt modulus;
  final BigInt exponent;
}

/// Supervisors issue override codes (release a held parcel, skip a missing scan). The
/// code is sealed to HQ so the audit service, not the handheld, can read it later.
class OverrideCodeSealer {
  OverrideCodeSealer(this.hqKey);

  final HqOverrideKey hqKey;

  String seal({
    required String code,
    required String supervisorId,
    required String reason,
  }) {
    final message = utf8.encode(
      jsonEncode({'code': code, 'supervisor': supervisorId, 'reason': reason}),
    );
    final cipher = OAEPEncoding(RSAEngine())
      ..init(
        true,
        PublicKeyParameter<RSAPublicKey>(
          RSAPublicKey(hqKey.modulus, hqKey.exponent),
        ),
      );
    final sealed = cipher.process(Uint8List.fromList(message));
    return '${hqKey.keyId}.${base64Url.encode(sealed)}';
  }
}

/// Override codes are 8 digits; the check digit is the sum of the others mod 10.
bool isValidOverrideCode(String code) {
  if (code.length != 8 || code.codeUnits.any((c) => c < 0x30 || c > 0x39)) {
    return false;
  }
  final digits = code.codeUnits.map((c) => c - 0x30).toList();
  return digits.take(7).fold<int>(0, (a, b) => a + b) % 10 == digits[7];
}
