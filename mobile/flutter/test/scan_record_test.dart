import 'package:flutter_test/flutter_test.dart';
import 'package:tallowbrook_scanner/scanning/scan_record.dart';

void main() {
  final record = ScanRecord(
    id: 'e1',
    barcode: 'TB123456789GB',
    depotCode: 'DPT4',
    action: ScanAction.toBin,
    scannedAt: DateTime.utc(2026, 10, 1, 7, 30),
    staffId: 's-104',
    binCode: 'B-12',
  );

  test('round-trips through JSON', () {
    final copy = ScanRecord.fromJson(record.toJson());
    expect(copy.toJson(), record.toJson());
  });

  test('canonical form leaves empty fields in place', () {
    expect(
      record.canonical(),
      'e1|TB123456789GB|DPT4|toBin|2026-10-01T07:30:00.000Z|s-104|B-12|',
    );
  });

  test('recognises Tallowbrook barcodes', () {
    expect(isTallowbrookBarcode('tb123456789gb'), isTrue);
    expect(isTallowbrookBarcode('TB12345678GB'), isFalse);
  });
}
