// The driver app keeps the day's route bundle for offline use (tunnels, rural depots).
// The bundle is sealed under the device's vault key, issued when the phone was paired.
import nacl from 'tweetnacl';

/**
 * @typedef {object} RouteBundle
 * @property {string} routeId
 * @property {string} driverId
 * @property {string} date
 * @property {{ shipmentId: string, address: string, window: string, notes: string | null }[]} stops
 */

/**
 * @returns {Uint8Array} a new vault key for a freshly paired device
 */
export function newVaultKey() {
  return nacl.randomBytes(nacl.secretbox.keyLength);
}

/**
 * @param {RouteBundle} bundle
 * @param {Uint8Array} vaultKey
 */
export function sealRouteBundle(bundle, vaultKey) {
  if (bundle.stops.length > 400) throw new Error('route bundle too large for the driver app');
  const payload = new TextEncoder().encode(JSON.stringify(bundle));
  const nonce = nacl.randomBytes(nacl.secretbox.nonceLength);
  const box = nacl.secretbox(payload, nonce, vaultKey);
  return {
    routeId: bundle.routeId,
    header: Buffer.from(nonce).toString('base64'),
    body: Buffer.from(box).toString('base64'),
    expiresAt: `${bundle.date}T23:59:59Z`,
  };
}
