import 'dart:convert';
import 'dart:io';

import 'package:cryptography/cryptography.dart';

import '../security/crypto_suite.dart';
import 'scan_record.dart';

/// Turns queue entries into bytes on disk and back.
abstract class QueueCodec {
  Future<List<int>> encode(List<int> plain);
  Future<List<int>> decode(List<int> stored);
}

/// The production codec: each entry is sealed with the queue key (see QueueKey).
class EncryptedQueueCodec implements QueueCodec {
  EncryptedQueueCodec(this.key);

  final SecretKey key;

  @override
  Future<List<int>> encode(List<int> plain) async {
    final box = await queueCipher.encrypt(plain, secretKey: key);
    return box.concatenation();
  }

  @override
  Future<List<int>> decode(List<int> stored) async {
    // 12-byte nonce ‖ ciphertext ‖ 16-byte tag, as concatenation() wrote it.
    final box = SecretBox.fromConcatenation(
      stored,
      nonceLength: 12,
      macLength: 16,
    );
    return queueCipher.decrypt(box, secretKey: key);
  }
}

/// Scans waiting for upload while the handheld is out of Wi-Fi range. One file per scan,
/// named so that a directory listing sorts in scan order.
class ScanQueueStore {
  ScanQueueStore(this.directory, this.codec);

  static const formatVersion = 2;

  final Directory directory;
  final QueueCodec codec;

  Future<void> add(ScanRecord record) async {
    await directory.create(recursive: true);
    final plain = utf8.encode(
      jsonEncode({'v': formatVersion, 'scan': record.toJson()}),
    );
    final stored = await codec.encode(plain);
    final name =
        '${record.scannedAt.toUtc().microsecondsSinceEpoch}-${record.id}.scan';
    await File('${directory.path}/$name').writeAsBytes(stored, flush: true);
  }

  Future<List<ScanRecord>> pending() async {
    if (!await directory.exists()) {
      return const [];
    }
    final files = await directory
        .list()
        .where((e) => e is File && e.path.endsWith('.scan'))
        .cast<File>()
        .toList();
    files.sort((a, b) => a.path.compareTo(b.path));
    final records = <ScanRecord>[];
    for (final file in files) {
      final plain = await codec.decode(await file.readAsBytes());
      final entry = jsonDecode(utf8.decode(plain)) as Map<String, Object?>;
      if (entry['v'] != formatVersion) {
        continue;
      }
      records.add(ScanRecord.fromJson(entry['scan']! as Map<String, Object?>));
    }
    return records;
  }

  Future<void> remove(ScanRecord record) async {
    await for (final entity in directory.list()) {
      if (entity is File && entity.path.endsWith('-${record.id}.scan')) {
        await entity.delete();
      }
    }
  }

  Future<int> count() async {
    if (!await directory.exists()) {
      return 0;
    }
    return directory.list().where((e) => e.path.endsWith('.scan')).length;
  }
}
