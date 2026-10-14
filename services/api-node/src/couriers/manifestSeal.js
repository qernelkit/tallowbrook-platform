// Courier manifests (stops, consignee names, access codes) are sealed to the courier's
// registered device key before they leave the gateway. The device key comes from the
// courier registry; each manifest uses a fresh ephemeral key.
import { createCipheriv, createPublicKey, diffieHellman, generateKeyPairSync, hkdfSync, randomBytes } from 'node:crypto';

/**
 * @typedef {object} CourierDevice
 * @property {string} courierId
 * @property {string} deviceKeyDer base64 SubjectPublicKeyInfo registered by the courier app
 */

/**
 * @typedef {object} ManifestStop
 * @property {number} sequence
 * @property {string} shipmentId
 * @property {string} consigneeName
 * @property {string} address
 * @property {string | null} accessCode
 */

/**
 * @param {CourierDevice} device
 * @param {{ routeId: string, date: string, stops: ManifestStop[] }} manifest
 */
export function sealCourierManifest(device, manifest) {
  const courierKey = createPublicKey({ key: Buffer.from(device.deviceKeyDer, 'base64'), format: 'der', type: 'spki' });
  const ephemeral = generateKeyPairSync('x25519');
  const shared = diffieHellman({ privateKey: ephemeral.privateKey, publicKey: courierKey });
  const salt = randomBytes(16);
  const sealKey = Buffer.from(hkdfSync('sha256', shared, salt, 'tb-courier-seal/v1', 32));
  const nonce = randomBytes(12);
  const aead = createCipheriv('chacha20-poly1305', sealKey, nonce, { authTagLength: 16 });
  const ciphertext = Buffer.concat([aead.update(JSON.stringify(manifest), 'utf8'), aead.final()]);
  const tag = aead.getAuthTag();
  const sealed = Buffer.concat([nonce, ciphertext, tag]).toString('base64');
  return {
    routeId: manifest.routeId,
    courierId: device.courierId,
    ephemeral: ephemeral.publicKey.export({ format: 'der', type: 'spki' }).toString('base64'),
    salt: salt.toString('base64'),
    sealed,
  };
}

/**
 * @param {ManifestStop[]} stops
 * @returns {ManifestStop[]}
 */
export function orderStops(stops) {
  const seen = new Set();
  return [...stops]
    .sort((a, b) => a.sequence - b.sequence)
    .filter((stop) => {
      if (seen.has(stop.shipmentId)) return false;
      seen.add(stop.shipmentId);
      return true;
    });
}
