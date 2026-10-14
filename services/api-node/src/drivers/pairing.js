// Pairs a driver's phone with the gateway. The phone shows a QR code holding its box
// key; the depot supervisor scans it, and the gateway answers with a pairing grant
// (driver id, vault key, refresh token) that only that phone can open.
import nacl from 'tweetnacl';

const PHONE_KEY_BYTES = 32;

/**
 * @typedef {object} PairingGrant
 * @property {string} driverId
 * @property {string} deviceId
 * @property {string} vaultKey base64
 * @property {string} refreshToken
 */

/**
 * @param {string} phoneKeyB64 from the phone's QR code
 */
export function parsePhoneKey(phoneKeyB64) {
  const phoneKey = new Uint8Array(Buffer.from(phoneKeyB64, 'base64'));
  if (phoneKey.length !== PHONE_KEY_BYTES) throw new Error('phone key has the wrong length');
  return phoneKey;
}

/**
 * @param {Uint8Array} phoneKey
 * @param {PairingGrant} grant
 */
export function sealPairingGrant(phoneKey, grant) {
  const gatewayBoxKeys = nacl.box.keyPair();
  const nonce = nacl.randomBytes(nacl.box.nonceLength);
  const message = new TextEncoder().encode(JSON.stringify(grant));
  const sealed = nacl.box(message, nonce, phoneKey, gatewayBoxKeys.secretKey);
  return {
    gateway: Buffer.from(gatewayBoxKeys.publicKey).toString('base64'),
    header: Buffer.from(nonce).toString('base64'),
    body: Buffer.from(sealed).toString('base64'),
  };
}
