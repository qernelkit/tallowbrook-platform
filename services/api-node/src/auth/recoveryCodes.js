// Ten single-use recovery codes per account, shown once at enrolment.
import * as argon2 from 'argon2';
import { randomInt } from 'node:crypto';

const ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
const CODE_COUNT = 10;

function randomCode() {
  let out = '';
  for (let i = 0; i < 10; i += 1) out += ALPHABET[randomInt(ALPHABET.length)];
  return `${out.slice(0, 5)}-${out.slice(5)}`;
}

/**
 * @param {string} input
 */
export function normaliseCode(input) {
  const compact = input.toUpperCase().replace(/[^A-Z0-9]/g, '');
  return compact.length === 10 ? `${compact.slice(0, 5)}-${compact.slice(5)}` : null;
}

/**
 * @returns {Promise<{ codes: string[], hashes: string[] }>}
 */
export async function generateRecoveryCodes() {
  const codes = [];
  const hashes = [];
  for (let i = 0; i < CODE_COUNT; i += 1) {
    const code = randomCode();
    codes.push(code);
    hashes.push(await argon2.hash(code));
  }
  return { codes, hashes };
}

/**
 * Returns the index of the matching stored code, or -1. The caller blanks that slot.
 * @param {(string | null)[]} stored
 * @param {string} input
 */
export async function redeemRecoveryCode(stored, input) {
  const code = normaliseCode(input);
  if (!code) return -1;
  for (const [index, hash] of stored.entries()) {
    if (hash && (await argon2.verify(hash, code))) return index;
  }
  return -1;
}
