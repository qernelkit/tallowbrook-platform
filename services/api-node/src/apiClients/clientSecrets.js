// API client secrets (machine-to-machine integrations). Only a derived value is
// stored; the secret is shown once when the client is created.
import { pbkdf2Sync, randomBytes, timingSafeEqual } from 'node:crypto';

/**
 * @param {string} clientSecret
 * @param {Buffer} [salt]
 * @returns {string} salt:derived, both base64
 */
export function hashClientSecret(clientSecret, salt = randomBytes(16)) {
  const derived = pbkdf2Sync(clientSecret, salt, 310_000, 32, 'sha256');
  return `${salt.toString('base64')}:${derived.toString('base64')}`;
}

/**
 * @param {string} clientSecret
 * @param {string} stored
 */
export function clientSecretMatches(clientSecret, stored) {
  const [saltB64] = stored.split(':');
  if (!saltB64) return false;
  const candidate = Buffer.from(hashClientSecret(clientSecret, Buffer.from(saltB64, 'base64')));
  const expected = Buffer.from(stored);
  return candidate.length === expected.length && timingSafeEqual(candidate, expected);
}

/**
 * @returns {{ clientId: string, clientSecret: string }}
 */
export function newClientCredentials() {
  return {
    clientId: `tbc_${randomBytes(9).toString('base64url')}`,
    clientSecret: `tbs_${randomBytes(32).toString('base64url')}`,
  };
}
