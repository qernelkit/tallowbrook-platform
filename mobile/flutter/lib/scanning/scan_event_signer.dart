import 'dart:convert';

import 'package:crypto/crypto.dart';

import '../api/api_signing_config.dart';
import 'scan_record.dart';

/// Signs a scan event for the WMS. Tests use a stub so they need no device secret.
abstract class ScanSigner {
  Map<String, String> headersFor(ScanRecord record);
}

class DeviceScanSigner implements ScanSigner {
  DeviceScanSigner(this.deviceSecret);

  /// The handheld's secret, provisioned at enrollment and kept in secure storage.
  final List<int> deviceSecret;

  @override
  Map<String, String> headersFor(ScanRecord record) {
    final bytes = utf8.encode(record.canonical());
    final mac = Hmac(scanSigningHash, deviceSecret).convert(bytes);
    final header = base64Url.encode(mac.bytes);
    return {scanSignatureHeader: header};
  }
}
