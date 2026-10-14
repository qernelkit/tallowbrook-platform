// Settlement instructions for Harbor Pay. Harbor Pay's intake expects a fresh data key
// per message, wrapped for their intake key, and the JSON payload sealed under it.
import { constants, createCipheriv, createPublicKey, publicEncrypt, randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { config } from '../config.js';

/** @type {import('node:crypto').KeyObject | undefined} */
let intakeKey;

function harborPayIntakeKey() {
  intakeKey ??= createPublicKey(readFileSync(config.partners.harborPayKeyFile, 'utf8'));
  return intakeKey;
}

/**
 * @typedef {object} SettlementInstruction
 * @property {string} instructionId
 * @property {string} payee
 * @property {number} amountMinor
 * @property {string} currency
 * @property {string} valueDate yyyy-mm-dd
 */

/**
 * @param {SettlementInstruction} instruction
 */
export function wrapForHarborPay(instruction) {
  const dataKey = randomBytes(32);
  const iv = randomBytes(12);
  const wrapped = publicEncrypt(
    {
      key: harborPayIntakeKey(),
      padding: constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256',
    },
    dataKey,
  );
  const aead = /** @type {import('node:crypto').CipherGCM} */ (createCipheriv('id-aes256-GCM', dataKey, iv));
  const body = Buffer.concat([aead.update(JSON.stringify(instruction), 'utf8'), aead.final()]);
  return {
    wrappedKey: wrapped.toString('base64'),
    iv: iv.toString('base64'),
    payload: body.toString('base64'),
    tag: aead.getAuthTag().toString('base64'),
    instructionId: instruction.instructionId,
  };
}

/**
 * @param {SettlementInstruction} instruction
 * @returns {string[]}
 */
export function instructionProblems(instruction) {
  const problems = [];
  if (!/^SI-\d{8}-\d{6}$/.test(instruction.instructionId)) problems.push('instructionId');
  if (!Number.isInteger(instruction.amountMinor) || instruction.amountMinor <= 0) problems.push('amountMinor');
  if (!/^[A-Z]{3}$/.test(instruction.currency)) problems.push('currency');
  if (!/^\d{4}-\d{2}-\d{2}$/.test(instruction.valueDate)) problems.push('valueDate');
  return problems;
}
