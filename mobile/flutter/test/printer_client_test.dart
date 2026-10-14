import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:tallowbrook_scanner/printing/label_printer_client.dart';

class FixedSigner implements PrinterRequestSigner {
  @override
  String sign(String payload) => 'fixed';
}

void main() {
  test('reports printer status', () async {
    final client = MockClient((request) async {
      expect(request.url.path, '/api/status');
      expect(request.url.queryParameters['sign'], 'fixed');
      return http.Response('{"ready": true, "labels_left": 240}', 200);
    });
    final printer = LabelPrinterClient(
      host: '10.4.0.21',
      signer: FixedSigner(),
      client: client,
    );

    final status = await printer.status();

    expect(status.ready, isTrue);
    expect(status.labelsLeft, 240);
  });

  test('raises on a printer error', () async {
    final client = MockClient((_) async => http.Response('jammed', 503));
    final printer = LabelPrinterClient(
      host: '10.4.0.21',
      signer: FixedSigner(),
      client: client,
    );

    expect(
      () => printer.printLabel('^XA^XZ'),
      throwsA(isA<PrinterException>()),
    );
  });
}
