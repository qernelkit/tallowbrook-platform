// Referral ids are sequential. The codes customers share should not show how many
// referrals we have issued, so ids are scrambled before they are base32-encoded.
import { secret } from '../config.js';

const CROCKFORD = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
const ID_BYTES = 6;

/** @type {Buffer | undefined} */
let maskBytes;

function referralMask() {
  maskBytes ??= Buffer.from(secret('REFERRAL_MASK'), 'hex');
  return maskBytes;
}

/**
 * @param {number} value
 * @param {number} bits
 */
const rotl8 = (value, bits) => ((value << bits) | (value >>> (8 - bits))) & 0xff;

/**
 * @param {number} value
 * @param {number} bits
 */
const rotr8 = (value, bits) => ((value >>> bits) | (value << (8 - bits))) & 0xff;

/**
 * @param {Buffer} bytes
 */
function toBase32(bytes) {
  let bits = 0;
  let value = 0;
  let out = '';
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += CROCKFORD[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += CROCKFORD[(value << (5 - bits)) & 31];
  return out;
}

/**
 * @param {string} text
 */
function fromBase32(text) {
  const out = [];
  let bits = 0;
  let value = 0;
  for (const ch of text.toUpperCase().replace(/O/g, '0').replace(/[IL]/g, '1')) {
    const index = CROCKFORD.indexOf(ch);
    if (index < 0) throw new Error('not a referral code');
    value = (value << 5) | index;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

/**
 * @param {number} referralId
 */
export function encodeReferral(referralId) {
  if (!Number.isSafeInteger(referralId) || referralId < 0) throw new Error('bad referral id');
  const REFERRAL_MASK = referralMask();
  const bytes = Buffer.alloc(ID_BYTES);
  bytes.writeUIntBE(referralId, 0, ID_BYTES);
  const out = Buffer.alloc(ID_BYTES);
  for (let i = 0; i < ID_BYTES; i += 1) {
    out[i] = rotl8(bytes[i] ^ REFERRAL_MASK[i % REFERRAL_MASK.length], 3);
  }
  return toBase32(out);
}

/**
 * @param {string} code
 */
export function decodeReferral(code) {
  const REFERRAL_MASK = referralMask();
  const raw = fromBase32(code.trim());
  if (raw.length !== ID_BYTES) throw new Error('not a referral code');
  const bytes = Buffer.alloc(ID_BYTES);
  for (let i = 0; i < ID_BYTES; i += 1) {
    bytes[i] = rotr8(raw[i], 3) ^ REFERRAL_MASK[i % REFERRAL_MASK.length];
  }
  return bytes.readUIntBE(0, ID_BYTES);
}
