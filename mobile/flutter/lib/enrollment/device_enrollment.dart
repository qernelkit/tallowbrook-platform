import 'dart:convert';

import 'package:cryptography/cryptography.dart';

/// What the device registry needs to enroll a handheld.
class EnrollmentRequest {
  EnrollmentRequest({
    required this.serialNumber,
    required this.depotCode,
    required this.model,
    required this.supervisorCode,
    required this.requestedAt,
  });

  final String serialNumber;
  final String depotCode;
  final String model;
  final String supervisorCode;
  final DateTime requestedAt;

  List<int> canonicalBytes() => utf8.encode(
    [
      serialNumber,
      depotCode,
      model,
      supervisorCode,
      requestedAt.toUtc().toIso8601String(),
    ].join('\n'),
  );
}

class SignedEnrollment {
  SignedEnrollment(this.request, this.publicKey, this.signature, this.seed);

  final EnrollmentRequest request;
  final List<int> publicKey;
  final List<int> signature;

  /// Stored in secure storage so the handheld can re-sign if the registry asks again.
  final List<int> seed;

  Map<String, Object?> toJson() => {
    'serial': request.serialNumber,
    'depot': request.depotCode,
    'model': request.model,
    'supervisor_code': request.supervisorCode,
    'requested_at': request.requestedAt.toUtc().toIso8601String(),
    'device_key': base64.encode(publicKey),
    'proof': base64.encode(signature),
  };
}

/// Enrolls a handheld with the device registry, once, when a supervisor sets it up.
class DeviceEnrollment {
  Future<SignedEnrollment> sign(EnrollmentRequest request) async {
    final algorithm = Ed25519();
    final keyPair = await algorithm.newKeyPair();
    final proof = await algorithm.sign(
      request.canonicalBytes(),
      keyPair: keyPair,
    );
    final publicKey = await keyPair.extractPublicKey();
    final seed = await keyPair.extractPrivateKeyBytes();
    return SignedEnrollment(request, publicKey.bytes, proof.bytes, seed);
  }
}
