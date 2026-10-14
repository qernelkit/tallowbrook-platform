// Callbacks from partners on the v2 integration (Atlas Freight, Harbor Pay) carry
// X-Partner-Mac: base64 of a MAC over the raw body with the partner's callback secret.
import { webcrypto } from 'node:crypto';

/** @type {Map<string, Promise<import('node:crypto').webcrypto.CryptoKey>>} */
const keyCache = new Map();

/**
 * @param {string} partnerId
 * @param {Buffer} secret
 */
function callbackKey(partnerId, secret) {
  let key = keyCache.get(partnerId);
  if (!key) {
    key = importCallbackKey(secret);
    keyCache.set(partnerId, key);
  }
  return key;
}

/**
 * @param {Buffer} secret
 */
async function importCallbackKey(secret) {
  const key = await webcrypto.subtle.importKey('raw', secret, { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
  return key;
}

/**
 * @param {string} partnerId
 * @param {Buffer} secret
 * @param {Buffer} rawBody
 * @param {string | undefined} header
 */
export async function partnerCallbackValid(partnerId, secret, rawBody, header) {
  if (!header) return false;
  const key = await callbackKey(partnerId, secret);
  return webcrypto.subtle.verify(key.algorithm, key, Buffer.from(header, 'base64'), rawBody);
}

/**
 * Drops cached keys after a partner rotates its secret.
 * @param {string} partnerId
 */
export function forgetPartnerKey(partnerId) {
  keyCache.delete(partnerId);
}
