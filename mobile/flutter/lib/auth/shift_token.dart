import 'package:dart_jsonwebtoken/dart_jsonwebtoken.dart';

/// The dock gateway lets a handheld open loading-bay doors during a shift. It checks a
/// token the handheld issues itself at sign-in, keyed with the per-device shift secret.
class ShiftToken {
  static const shiftLength = Duration(hours: 10);

  static String issue({
    required String staffId,
    required String depotCode,
    required String deviceSerial,
    required String shiftSecret,
  }) {
    final claims = {
      'sub': staffId,
      'depot': depotCode,
      'device': deviceSerial,
      'scope': 'dock-doors',
    };
    final jwt = JWT(claims, issuer: 'scanner');
    final token = jwt.sign(SecretKey(shiftSecret), expiresIn: shiftLength);
    return token;
  }
}
