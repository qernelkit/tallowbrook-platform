import 'dart:convert';
import 'dart:typed_data';

import 'package:pointycastle/export.dart';

/// Label templates (ZPL with placeholders) pushed from HQ as one encrypted bundle, so
/// customer-facing label layouts cannot be swapped on a handheld.
class TemplateBundle {
  TemplateBundle(this.templates);

  final Map<String, String> templates;

  /// [sealed] is nonce (12 bytes) ‖ ciphertext ‖ tag; the bundle id is the associated data.
  static TemplateBundle open(
    Uint8List sealed, {
    required Uint8List bundleKey,
    required String bundleId,
  }) {
    final nonce = sealed.sublist(0, 12);
    final body = sealed.sublist(12);
    final aad = Uint8List.fromList(utf8.encode(bundleId));
    final cipher = GCMBlockCipher(AESEngine())
      ..init(false, AEADParameters(KeyParameter(bundleKey), 128, nonce, aad));
    final plain = cipher.process(body);
    final json = jsonDecode(utf8.decode(plain)) as Map<String, Object?>;
    return TemplateBundle(
      json.map((name, zpl) => MapEntry(name, zpl! as String)),
    );
  }

  String render(String name, Map<String, String> fields) {
    final template = templates[name];
    if (template == null) {
      throw ArgumentError.value(name, 'name', 'no such label template');
    }
    return template.replaceAllMapped(
      RegExp(r'\{\{(\w+)\}\}'),
      (m) => fields[m[1]] ?? '',
    );
  }
}
