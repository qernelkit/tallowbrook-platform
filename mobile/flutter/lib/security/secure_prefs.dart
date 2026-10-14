import 'package:flutter_secure_storage/flutter_secure_storage.dart';

/// Device secrets: the scan-signing secret, the shift secret, the printer secret, the
/// enrollment key and the device salt. Nothing here is synced or backed up.
class SecurePrefs {
  SecurePrefs([FlutterSecureStorage? storage])
    : _storage = storage ?? _defaultStorage;

  static const _defaultStorage = FlutterSecureStorage(
    aOptions: AndroidOptions(
      keyCipherAlgorithm:
          KeyCipherAlgorithm.RSA_ECB_OAEPwithSHA_256andMGF1Padding,
      storageCipherAlgorithm: StorageCipherAlgorithm.AES_GCM_NoPadding,
      migrateWithBackup: true,
    ),
  );

  static const deviceSecretKey = 'device.scan_secret';
  static const shiftSecretKey = 'device.shift_secret';
  static const printerSecretKey = 'printer.api_secret';
  static const deviceSaltKey = 'device.salt';
  static const enrollmentSeedKey = 'device.enrollment_seed';
  static const batchKeyKey = 'device.batch_key';

  final FlutterSecureStorage _storage;

  Future<String?> read(String key) => _storage.read(key: key);

  Future<void> write(String key, String value) =>
      _storage.write(key: key, value: value);

  Future<void> delete(String key) => _storage.delete(key: key);

  Future<void> wipe() => _storage.deleteAll();
}
