// Registration options for shipper passkeys. The browser ceremony and the
// attestation check happen in the account routes.
import { generateRegistrationOptions } from '@simplewebauthn/server';
import { config } from '../config.js';

/**
 * @typedef {object} StoredPasskey
 * @property {string} credentialId base64url
 * @property {string[]} transports
 * @property {Date} createdAt
 * @property {string} label
 */

/**
 * @param {{ id: string, email: string, displayName: string }} account
 * @param {StoredPasskey[]} existing
 */
export async function passkeyRegistrationOptions(account, existing) {
  if (existing.length >= 10) throw new Error('too many passkeys registered');
  return generateRegistrationOptions({
    rpName: config.passkeys.rpName,
    rpID: config.passkeys.rpId,
    userName: account.email,
    userDisplayName: account.displayName,
    userID: new TextEncoder().encode(account.id),
    attestationType: 'none',
    excludeCredentials: existing.map((stored) => ({ id: stored.credentialId, transports: stored.transports })),
    authenticatorSelection: { residentKey: 'preferred', userVerification: 'preferred' },
    supportedAlgorithmIDs: [-8, -7, -257],
    timeout: 120_000,
  });
}

/**
 * @param {StoredPasskey[]} existing
 * @param {string} label
 */
export function labelIsFree(existing, label) {
  const wanted = label.trim().toLowerCase();
  return wanted.length > 0 && !existing.some((stored) => stored.label.toLowerCase() === wanted);
}
