// Free-text PII that lives outside the CSFLE collections (delivery notes, claim
// descriptions, stored device keys) is sealed per tenant. Each tenant key is derived
// from the field master key and the tenant's salt, so rotating the master key
// re-derives every tenant key at once.
import { createCipheriv, createDecipheriv, hkdfSync, randomBytes } from 'node:crypto';
import { secretBytes } from '../config.js';

const FIELD_CIPHER = 'aes-256-gcm';
const FIELD_KEY_INFO = 'tb-pii-fields/v1';
const FORMAT_VERSION = 'f1';
const IV_BYTES = 12;

/**
 * @typedef {{ id: string, fieldSalt: Buffer }} TenantKeying
 */

/**
 * @param {Buffer} masterKey
 * @param {Buffer} tenantSalt
 */
function tenantKey(masterKey, tenantSalt) {
  const key = Buffer.from(hkdfSync('sha256', masterKey, tenantSalt, FIELD_KEY_INFO, 32));
  return key;
}

/**
 * Seals bytes under a 32-byte key; output is iv | body | tag.
 * @param {Buffer | Uint8Array} key
 * @param {Buffer} plaintext
 * @param {Buffer} aad
 */
export function aeadSeal(key, plaintext, aad) {
  const iv = randomBytes(IV_BYTES);
  const enc = createCipheriv(FIELD_CIPHER, key, iv);
  enc.setAAD(aad);
  const body = Buffer.concat([enc.update(plaintext), enc.final()]);
  return Buffer.concat([iv, body, enc.getAuthTag()]);
}

/**
 * @param {Buffer | Uint8Array} key
 * @param {Buffer} sealed
 * @param {Buffer} aad
 */
export function aeadOpen(key, sealed, aad) {
  const iv = sealed.subarray(0, IV_BYTES);
  const tag = sealed.subarray(sealed.length - 16);
  const dec = createDecipheriv(FIELD_CIPHER, key, iv);
  dec.setAAD(aad);
  dec.setAuthTag(tag);
  return Buffer.concat([dec.update(sealed.subarray(IV_BYTES, sealed.length - 16)), dec.final()]);
}

/**
 * @param {TenantKeying} tenant
 * @param {string} value
 * @param {Buffer} [masterKey]
 * @returns {string}
 */
export function sealField(tenant, value, masterKey = secretBytes('FIELD_MASTER_KEY')) {
  const sealed = aeadSeal(tenantKey(masterKey, tenant.fieldSalt), Buffer.from(value, 'utf8'), Buffer.from(tenant.id));
  return `${FORMAT_VERSION}.${sealed.toString('base64url')}`;
}

/**
 * @param {TenantKeying} tenant
 * @param {string} stored
 * @param {Buffer} [masterKey]
 * @returns {string}
 */
export function openField(tenant, stored, masterKey = secretBytes('FIELD_MASTER_KEY')) {
  const [version, payload] = stored.split('.');
  if (version !== FORMAT_VERSION || !payload) throw new Error('unknown sealed field format');
  const plain = aeadOpen(tenantKey(masterKey, tenant.fieldSalt), Buffer.from(payload, 'base64url'), Buffer.from(tenant.id));
  return plain.toString('utf8');
}

/**
 * @param {string} value
 */
export function isSealedField(value) {
  return typeof value === 'string' && value.startsWith(`${FORMAT_VERSION}.`);
}
