// Webhook endpoint secrets. A rotation keeps the previous secret for 24 hours so
// shippers can deploy the new one without dropping deliveries.
import { generateKeySync } from 'node:crypto';
import { collection } from '../db/collections.js';

const OVERLAP_MS = 24 * 60 * 60 * 1000;

export function newEndpointSecret() {
  const secret = generateKeySync('hmac', { length: 512 });
  return `whsec_${secret.export().toString('base64url')}`;
}

/**
 * @param {import('mongodb').Db} db
 * @param {string} tenantId
 * @param {string} endpointId
 * @returns {Promise<string | null>} the new secret, shown once
 */
export async function rotateEndpointSecret(db, tenantId, endpointId) {
  const endpoints = collection(db, 'webhookEndpoints');
  const endpoint = await endpoints.findOne({ _id: endpointId, tenantId });
  if (!endpoint) return null;
  const fresh = newEndpointSecret();
  await endpoints.updateOne(
    { _id: endpointId },
    {
      $set: {
        secret: fresh,
        previousSecret: endpoint.secret,
        previousSecretExpiresAt: new Date(Date.now() + OVERLAP_MS),
        rotatedAt: new Date(),
      },
    },
  );
  return fresh;
}
