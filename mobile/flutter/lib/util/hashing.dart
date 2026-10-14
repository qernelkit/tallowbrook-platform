import 'package:collection/collection.dart';

/// A parcel in a bin: the key the scan screen groups by.
class ScanKey {
  const ScanKey(this.sku, this.binCode);

  final String sku;
  final String binCode;

  @override
  bool operator ==(Object other) =>
      other is ScanKey && other.sku == sku && other.binCode == binCode;

  @override
  int get hashCode => Object.hash(sku, binCode);

  @override
  String toString() => '$sku@$binCode';
}

/// One line of a truck manifest.
class ScanLine {
  const ScanLine(this.barcode, this.stop);

  final String barcode;
  final int stop;

  @override
  bool operator ==(Object other) =>
      other is ScanLine && other.barcode == barcode && other.stop == stop;

  @override
  int get hashCode => Object.hash(barcode, stop);
}

/// Cheap change detection: the manifest screen only rebuilds when this changes.
int manifestHash(List<ScanLine> lines) =>
    const DeepCollectionEquality().hash(lines);
