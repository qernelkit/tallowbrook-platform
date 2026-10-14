// Kiosk pairing. The kiosk firmware only speaks uncompressed P-256 points, so the
// gateway does the exchange with the classic ECDH API. Both screens show a six-digit
// code derived from the shared value, and the supervisor confirms they match.
import { createECDH } from 'node:crypto';

const UNCOMPRESSED_POINT = /^04[0-9a-f]{128}$/i;

/**
 * @param {Buffer} shared
 */
function confirmationCode(shared) {
  return String(shared.readUInt32BE(0) % 1_000_000).padStart(6, '0');
}

/**
 * @param {string} kioskPointHex
 */
export function pairKiosk(kioskPointHex) {
  if (!UNCOMPRESSED_POINT.test(kioskPointHex)) throw new Error('kiosk point must be uncompressed');
  const exchange = createECDH('prime256v1');
  exchange.generateKeys();
  const shared = exchange.computeSecret(Buffer.from(kioskPointHex, 'hex'));
  return {
    gatewayPoint: exchange.getPublicKey('hex', 'uncompressed'),
    confirmationCode: confirmationCode(shared),
    channelKey: shared,
  };
}
