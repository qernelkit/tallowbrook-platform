// Authenticator-app second factor. Codes use the otplib defaults, which every
// authenticator app our shippers use understands.
import { generateSecret, generateURI, verify } from 'otplib';
import { config } from '../config.js';

/**
 * @typedef {object} AuthenticatorEnrolment
 * @property {string} secret base32
 * @property {Date} createdAt
 * @property {Date | null} confirmedAt
 */

/**
 * @param {{ email: string }} account
 * @returns {{ enrolment: AuthenticatorEnrolment, uri: string }}
 */
export function startAuthenticatorEnrolment(account) {
  const enrolment = { secret: generateSecret(), createdAt: new Date(), confirmedAt: null };
  const uri = generateURI({ issuer: config.passkeys.rpName, label: account.email, secret: enrolment.secret });
  return { enrolment, uri };
}

/**
 * @param {AuthenticatorEnrolment} enrolment
 * @param {string} token six digits typed by the user
 * @returns {Promise<boolean>}
 */
export async function checkAuthenticatorCode(enrolment, token) {
  if (!/^\d{6}$/.test(token)) return false;
  const result = await verify({ secret: enrolment.secret, token });
  return result.valid;
}
