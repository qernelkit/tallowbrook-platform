import 'package:archive/archive.dart';
import 'package:crypto/crypto.dart';

/// Damage photos are retried a lot on depot Wi-Fi. Before uploading, the scanner checks
/// the photo against the camera's sidecar CRC (to catch truncated files) and skips
/// photos it has already uploaded.
class PhotoDedupe {
  final Set<String> _uploaded = {};

  /// Returns the photo's content id, or null if it was uploaded already.
  /// Throws [StateError] when the file does not match the camera's CRC.
  String? admit(List<int> bytes, {required int sidecarCrc}) {
    final fingerprint = sha256.convert(bytes).toString();
    final crc = getCrc32(bytes);
    if (crc != sidecarCrc) {
      throw StateError('Photo is incomplete (CRC mismatch); retake it');
    }
    if (!_uploaded.add(fingerprint)) {
      return null;
    }
    return fingerprint;
  }

  void forget(String contentId) => _uploaded.remove(contentId);

  int get uploadedCount => _uploaded.length;
}
