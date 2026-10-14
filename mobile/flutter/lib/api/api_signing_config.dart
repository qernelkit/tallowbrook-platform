import 'package:crypto/crypto.dart';

/// Endpoints of the warehouse management API and how scan events are signed for it.
const wmsBaseUrl = 'https://wms.tallowbrook.example/api/v3';
const scanEventsPath = '/scan-events';
const scanBatchesPath = '/scan-batches';
const devicesPath = '/devices';
const damagePhotosPath = '/damage-photos';

/// Header carrying the per-event MAC, and the hash the WMS expects inside it.
const scanSignatureHeader = 'X-Scan-Signature';
const scanSigningHash = sha256;
