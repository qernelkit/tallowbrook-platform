import 'dart:convert';

import 'package:crypto/crypto.dart';
import 'package:http/http.dart' as http;

/// Computes the `sign` query parameter the printer firmware checks.
abstract class PrinterRequestSigner {
  String sign(String payload);
}

/// The firmware's scheme: hex digest of the shared printer secret followed by the payload.
class FirmwareRequestSigner implements PrinterRequestSigner {
  FirmwareRequestSigner(this.printerSecret);

  final String printerSecret;

  @override
  String sign(String payload) {
    final sign = md5.convert(utf8.encode('$printerSecret$payload')).toString();
    return sign;
  }
}

/// The label printers' HTTP API on the depot network.
class LabelPrinterClient {
  LabelPrinterClient({
    required this.host,
    required this.signer,
    http.Client? client,
  }) : _client = client ?? http.Client();

  final String host;
  final PrinterRequestSigner signer;
  final http.Client _client;

  Future<void> printLabel(String zpl, {int copies = 1, DateTime? now}) async {
    final ts = ((now ?? DateTime.now()).millisecondsSinceEpoch ~/ 1000)
        .toString();
    final payload =
        'copies=$copies&ts=$ts&zpl=${Uri.encodeQueryComponent(zpl)}';
    final response = await _client.post(
      Uri.http(host, '/api/print', {
        'ts': ts,
        'copies': '$copies',
        'sign': signer.sign(payload),
      }),
      headers: {'Content-Type': 'text/plain; charset=utf-8'},
      body: zpl,
    );
    if (response.statusCode != 200) {
      throw PrinterException(response.statusCode, response.body);
    }
  }

  Future<PrinterStatus> status() async {
    final ts = (DateTime.now().millisecondsSinceEpoch ~/ 1000).toString();
    final response = await _client.get(
      Uri.http(host, '/api/status', {'ts': ts, 'sign': signer.sign('ts=$ts')}),
    );
    if (response.statusCode != 200) {
      throw PrinterException(response.statusCode, response.body);
    }
    return PrinterStatus.fromJson(
      jsonDecode(response.body) as Map<String, Object?>,
    );
  }

  void close() => _client.close();
}

class PrinterStatus {
  PrinterStatus({required this.ready, required this.labelsLeft, this.error});

  factory PrinterStatus.fromJson(Map<String, Object?> json) => PrinterStatus(
    ready: json['ready'] == true,
    labelsLeft: (json['labels_left'] as num?)?.toInt() ?? 0,
    error: json['error'] as String?,
  );

  final bool ready;
  final int labelsLeft;
  final String? error;
}

class PrinterException implements Exception {
  PrinterException(this.statusCode, this.body);

  final int statusCode;
  final String body;

  @override
  String toString() => 'Printer returned $statusCode: $body';
}
