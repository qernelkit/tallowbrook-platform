import 'dart:math';
import 'dart:typed_data';

import 'package:pointycastle/export.dart';

/// The handheld's key for signing scan batches. Created once at enrollment; the public
/// half is registered with the WMS, the private half stays in secure storage.
class BatchSigningKey {
  BatchSigningKey._(this.privateKey, this.publicKey);

  final ECPrivateKey privateKey;
  final ECPublicKey publicKey;

  static final domain = ECCurve_secp256r1();

  static BatchSigningKey generate() {
    final secure = Random.secure();
    final seed = Uint8List.fromList(
      List<int>.generate(32, (_) => secure.nextInt(256)),
    );
    final random = FortunaRandom()..seed(KeyParameter(seed));
    final generator = ECKeyGenerator()
      ..init(ParametersWithRandom(ECKeyGeneratorParameters(domain), random));
    final pair = generator.generateKeyPair();
    return BatchSigningKey._(pair.privateKey, pair.publicKey);
  }

  /// Restores the key saved by [encodePrivate].
  static BatchSigningKey decode(String stored) {
    final d = BigInt.parse(stored, radix: 16);
    final q = domain.G * d;
    return BatchSigningKey._(ECPrivateKey(d, domain), ECPublicKey(q, domain));
  }

  String encodePrivate() => privateKey.d!.toRadixString(16);

  /// Uncompressed point, as the WMS device registry stores it.
  Uint8List encodePublic() => publicKey.Q!.getEncoded(false);
}
