// Business tenants can sign their API requests (bulk booking uploads) instead of using
// a bearer key. The gateway creates the pair, keeps the private half sealed for the
// tenant's own download once, and stores the public half for verification.
import { generateKeyPairSync, randomUUID } from 'node:crypto';
import { sealField } from '../crypto/fieldCipher.js';
import { collection } from '../db/collections.js';

/**
 * @param {import('mongodb').Db} db
 * @param {{ id: string, fieldSalt: Buffer }} tenant
 * @param {string} label
 */
export async function createTenantRequestKey(db, tenant, label) {
  const active = await collection(db, 'tenantApiKeys').countDocuments({ tenantId: tenant.id, revokedAt: null });
  if (active >= 5) throw new Error('tenant already has five active request keys');
  const { publicKey: verifyPem, privateKey: privatePem } = generateKeyPairSync('rsa', {
    modulusLength: 3072,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
  const keyId = `tk_${randomUUID().replace(/-/g, '').slice(0, 20)}`;
  await collection(db, 'tenantApiKeys').insertOne({
    _id: keyId,
    tenantId: tenant.id,
    label: label.slice(0, 64),
    verifyPem,
    privatePem: sealField(tenant, privatePem),
    downloadedAt: null,
    createdAt: new Date(),
    revokedAt: null,
  });
  return { keyId, verifyPem };
}

/**
 * @param {import('mongodb').Db} db
 * @param {string} tenantId
 * @param {string} keyId
 */
export async function revokeTenantRequestKey(db, tenantId, keyId) {
  const result = await collection(db, 'tenantApiKeys').updateOne(
    { _id: keyId, tenantId, revokedAt: null },
    { $set: { revokedAt: new Date() } },
  );
  return result.modifiedCount === 1;
}
