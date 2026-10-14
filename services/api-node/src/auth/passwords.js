// Customer passwords. New and updated passwords use argon2id with the OWASP minimum
// profile; accounts imported from the 2019 customer portal keep the portal's format
// until the customer next signs in, when they are rehashed.
import * as argon2 from 'argon2';
import { scryptSync, timingSafeEqual } from 'node:crypto';

const MIN_LENGTH = 12;
const MAX_LENGTH = 256;
const IMPORTED_SCHEME = 'portal-2019';

/**
 * @param {string} password
 * @returns {string[]} problems, empty when acceptable
 */
export function passwordProblems(password) {
  const problems = [];
  if (password.length < MIN_LENGTH) problems.push(`at least ${MIN_LENGTH} characters`);
  if (password.length > MAX_LENGTH) problems.push(`at most ${MAX_LENGTH} characters`);
  if (/^\s|\s$/.test(password)) problems.push('no leading or trailing spaces');
  if (new Set(password).size < 5) problems.push('more than four distinct characters');
  return problems;
}

/**
 * @param {string} password
 * @returns {Promise<string>}
 */
export function hashPassword(password) {
  return argon2.hash(password, {
    type: argon2.argon2id,
    memoryCost: 19456,
    timeCost: 2,
    parallelism: 1,
  });
}

/**
 * @typedef {object} StoredCredential
 * @property {string} scheme 'argon2' or the imported portal scheme
 * @property {string} hash
 */

/**
 * @param {StoredCredential} stored
 * @param {string} password
 * @returns {Promise<{ ok: boolean, rehash: boolean }>}
 */
export async function checkPassword(stored, password) {
  if (stored.scheme === IMPORTED_SCHEME) {
    return { ok: importedPasswordMatches(stored.hash, password), rehash: true };
  }
  return { ok: await argon2.verify(stored.hash, password), rehash: false };
}

/**
 * The portal stored base64(salt) "$" base64(64-byte key).
 * @param {string} stored
 * @param {string} password
 */
function importedPasswordMatches(stored, password) {
  const [saltB64, keyB64] = stored.split('$');
  if (!saltB64 || !keyB64) return false;
  const salt = Buffer.from(saltB64, 'base64');
  const candidate = scryptSync(password, salt, 64, { N: 16384, r: 8, p: 1 });
  const expected = Buffer.from(keyB64, 'base64');
  return expected.length === candidate.length && timingSafeEqual(candidate, expected);
}
