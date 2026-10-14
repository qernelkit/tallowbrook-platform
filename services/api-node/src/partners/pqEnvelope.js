// Customs pre-clearance envelope pilot. Each recipient publishes an encapsulation key;
// the shared secret seals the declaration bundle.
import { readFileSync } from 'node:fs';
import { ml_kem1024, ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { config } from '../config.js';
import { aeadSeal } from '../crypto/fieldCipher.js';

// Harbor customs asked for the larger parameter set; other pilot partners use the default.
const KEM_BY_RECIPIENT = {
  'harbor-customs': ml_kem1024,
  default: ml_kem768,
};

/** @type {Map<string, Uint8Array>} */
const recipientKeys = new Map();

/**
 * @param {string} recipient
 */
function recipientKey(recipient) {
  let key = recipientKeys.get(recipient);
  if (!key) {
    const files = config.partners.envelopeKeyFiles;
    key = new Uint8Array(readFileSync(files[recipient] ?? files.default));
    recipientKeys.set(recipient, key);
  }
  return key;
}

/**
 * @param {string} recipient
 * @param {object} bundle
 */
export function sealForRecipient(recipient, bundle) {
  const kem = KEM_BY_RECIPIENT[recipient] ?? KEM_BY_RECIPIENT.default;
  const { cipherText, sharedSecret } = kem.encapsulate(recipientKey(recipient));
  const sealed = aeadSeal(sharedSecret, Buffer.from(JSON.stringify(bundle)), Buffer.from(recipient));
  return {
    recipient,
    encapsulated: Buffer.from(cipherText).toString('base64'),
    sealed: sealed.toString('base64'),
    createdAt: new Date().toISOString(),
  };
}
