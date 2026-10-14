import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:tallowbrook_scanner/scanning/scan_queue_store.dart';
import 'package:tallowbrook_scanner/scanning/scan_record.dart';

/// Stores entries as they are; the encrypted codec is exercised on devices.
class PassThroughCodec implements QueueCodec {
  @override
  Future<List<int>> encode(List<int> plain) async => plain;

  @override
  Future<List<int>> decode(List<int> stored) async => stored;
}

ScanRecord scan(String id, int minute) => ScanRecord(
  id: id,
  barcode: 'TB00000000${minute}GB',
  depotCode: 'DPT4',
  action: ScanAction.inbound,
  scannedAt: DateTime.utc(2026, 10, 1, 8, minute),
  staffId: 's-1',
);

void main() {
  late Directory dir;

  setUp(() async => dir = await Directory.systemTemp.createTemp('queue'));
  tearDown(() async => dir.delete(recursive: true));

  test('returns scans in the order they were made', () async {
    final store = ScanQueueStore(dir, PassThroughCodec());
    await store.add(scan('b', 5));
    await store.add(scan('a', 1));
    final pending = await store.pending();
    expect(pending.map((s) => s.id), ['a', 'b']);
  });

  test('removes an uploaded scan', () async {
    final store = ScanQueueStore(dir, PassThroughCodec());
    final first = scan('a', 1);
    await store.add(first);
    await store.add(scan('b', 2));
    await store.remove(first);
    expect(await store.count(), 1);
  });
}
