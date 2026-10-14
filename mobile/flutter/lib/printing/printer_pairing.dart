import 'dart:developer';

import 'package:cryptography/cryptography.dart';

import '../security/crypto_suite.dart';

/// The Bluetooth side of a label printer, as the platform channel exposes it.
abstract class PrinterLink {
  String get printerId;
  Future<List<int>> readPublicKey();
  Future<List<int>> readPairingChallenge();
  Future<void> writePublicKey(List<int> key);
  Future<void> writeJob(List<int> nonce, List<int> ciphertext, List<int> tag);
}

/// A paired printer: print jobs are sealed under a key agreed when the printer was
/// paired, so labels (names, addresses) are not readable over the air.
class PrinterSession {
  PrinterSession(this.link, this._sessionKey);

  final PrinterLink link;
  final SecretKey _sessionKey;

  Future<void> send(List<int> job) async {
    final box = await printerChannelCipher.encrypt(job, secretKey: _sessionKey);
    await link.writeJob(box.nonce, box.cipherText, box.mac.bytes);
  }
}

class PrinterPairing {
  Future<PrinterSession> pair(PrinterLink link) async {
    log('Starting key exchange with printer ${link.printerId}');
    final keyExchange = X25519();
    final ours = await keyExchange.newKeyPair();
    final printerKey = SimplePublicKey(
      await link.readPublicKey(),
      type: KeyPairType.x25519,
    );
    final shared = await keyExchange.sharedSecretKey(
      keyPair: ours,
      remotePublicKey: printerKey,
    );
    final ourPublic = await ours.extractPublicKey();
    await link.writePublicKey(ourPublic.bytes);
    final challenge = await link.readPairingChallenge();
    final sessionKey = await printerKdf.deriveKey(
      secretKey: shared,
      nonce: challenge,
    );
    log('Paired with printer ${link.printerId}');
    return PrinterSession(link, sessionKey);
  }
}
