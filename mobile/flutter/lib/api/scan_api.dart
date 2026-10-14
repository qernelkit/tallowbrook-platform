import 'dart:convert';
import 'dart:typed_data';

import 'package:http/http.dart' as http;

import '../scanning/batch_signer.dart';
import '../scanning/scan_event_signer.dart';
import '../scanning/scan_record.dart';
import 'api_signing_config.dart';

class ScanApiException implements Exception {
  ScanApiException(this.statusCode, this.message);

  final int statusCode;
  final String message;

  bool get isRetryable => statusCode >= 500 || statusCode == 429;

  @override
  String toString() => 'WMS returned $statusCode: $message';
}

/// The warehouse management API, as the scanner uses it.
class ScanApi {
  ScanApi({
    required this.deviceSerial,
    required this.signer,
    required this.batchSigner,
    required this.accessToken,
    http.Client? client,
  }) : _client = client ?? http.Client();

  final String deviceSerial;
  final ScanSigner signer;
  final BatchSigner batchSigner;
  final String accessToken;
  final http.Client _client;

  Map<String, String> get _baseHeaders => {
    'Authorization': 'Bearer $accessToken',
    'X-Device-Serial': deviceSerial,
  };

  Future<void> postScan(ScanRecord record) async {
    final response = await _client.post(
      Uri.parse('$wmsBaseUrl$scanEventsPath'),
      headers: {
        ..._baseHeaders,
        ...signer.headersFor(record),
        'Content-Type': 'application/json',
      },
      body: jsonEncode(record.toJson()),
    );
    _check(response);
  }

  /// Uploads queued scans in one batch, signed with the handheld's batch key.
  Future<void> postBatch(List<ScanRecord> records) async {
    final body = Uint8List.fromList(
      utf8.encode(
        jsonEncode({
          'device': deviceSerial,
          'events': [for (final r in records) r.toJson()],
        }),
      ),
    );
    final response = await _client.post(
      Uri.parse('$wmsBaseUrl$scanBatchesPath'),
      headers: {
        ..._baseHeaders,
        'Content-Type': 'application/json',
        'X-Batch-Signature': base64.encode(batchSigner.sign(body)),
      },
      body: body,
    );
    _check(response);
  }

  Future<void> uploadDamagePhoto(
    String contentId,
    String barcode,
    List<int> jpeg,
  ) async {
    final request =
        http.MultipartRequest('POST', Uri.parse('$wmsBaseUrl$damagePhotosPath'))
          ..headers.addAll(_baseHeaders)
          ..fields['barcode'] = barcode
          ..fields['content_id'] = contentId
          ..files.add(
            http.MultipartFile.fromBytes(
              'photo',
              jpeg,
              filename: '$contentId.jpg',
            ),
          );
    final response = await http.Response.fromStream(
      await _client.send(request),
    );
    _check(response);
  }

  void _check(http.Response response) {
    if (response.statusCode < 200 || response.statusCode >= 300) {
      throw ScanApiException(response.statusCode, response.body);
    }
  }

  void close() => _client.close();
}
