/// One scan of a parcel barcode at a depot.
class ScanRecord {
  ScanRecord({
    required this.id,
    required this.barcode,
    required this.depotCode,
    required this.action,
    required this.scannedAt,
    required this.staffId,
    this.binCode,
    this.truckId,
    this.damageNote,
  });

  factory ScanRecord.fromJson(Map<String, Object?> json) => ScanRecord(
    id: json['id']! as String,
    barcode: json['barcode']! as String,
    depotCode: json['depot']! as String,
    action: ScanAction.values.byName(json['action']! as String),
    scannedAt: DateTime.parse(json['scanned_at']! as String),
    staffId: json['staff_id']! as String,
    binCode: json['bin'] as String?,
    truckId: json['truck'] as String?,
    damageNote: json['damage_note'] as String?,
  );

  final String id;
  final String barcode;
  final String depotCode;
  final ScanAction action;
  final DateTime scannedAt;
  final String staffId;
  final String? binCode;
  final String? truckId;
  final String? damageNote;

  bool get isDamage => action == ScanAction.damage;

  Map<String, Object?> toJson() => {
    'id': id,
    'barcode': barcode,
    'depot': depotCode,
    'action': action.name,
    'scanned_at': scannedAt.toUtc().toIso8601String(),
    'staff_id': staffId,
    if (binCode != null) 'bin': binCode,
    if (truckId != null) 'truck': truckId,
    if (damageNote != null) 'damage_note': damageNote,
  };

  /// The fields the WMS checks the event MAC over, in its order.
  String canonical() => [
    id,
    barcode,
    depotCode,
    action.name,
    scannedAt.toUtc().toIso8601String(),
    staffId,
    binCode ?? '',
    truckId ?? '',
  ].join('|');
}

enum ScanAction { inbound, toBin, toTruck, outbound, damage, returned }

/// Barcodes on Tallowbrook labels: two letters, nine digits, two letters (TB123456789GB).
final _barcodePattern = RegExp(r'^[A-Z]{2}\d{9}[A-Z]{2}$');

bool isTallowbrookBarcode(String value) =>
    _barcodePattern.hasMatch(value.trim().toUpperCase());
