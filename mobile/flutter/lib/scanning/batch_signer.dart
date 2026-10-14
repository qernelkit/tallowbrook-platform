import 'dart:typed_data';

import 'package:pointycastle/export.dart';

import 'batch_signing_key.dart';

/// Signs an uploaded scan batch (the canonical JSON of its events). Signatures are the
/// 64-byte r ‖ s form the WMS verifies.
class BatchSigner {
  BatchSigner(this._key);

  final BatchSigningKey _key;

  Uint8List sign(Uint8List batch) {
    final signer = ECDSASigner(SHA256Digest(), HMac(SHA256Digest(), 64));
    signer.init(true, PrivateKeyParameter<ECPrivateKey>(_key.privateKey));
    final signature = signer.generateSignature(batch) as ECSignature;
    return Uint8List.fromList([
      ..._fixed32(signature.r),
      ..._fixed32(signature.s),
    ]);
  }

  static List<int> _fixed32(BigInt value) {
    final bytes = List<int>.filled(32, 0);
    var v = value;
    for (var i = 31; i >= 0; i--) {
      bytes[i] = (v & BigInt.from(0xff)).toInt();
      v = v >> 8;
    }
    return bytes;
  }
}
