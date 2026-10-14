// The customer-pii data key lives in the key vault collection. It is created once,
// the first time a gateway starts against an empty vault.
import { readFileSync } from 'node:fs';
import { ClientEncryption } from 'mongodb';
import { config } from '../config.js';
import { childLogger } from '../logger.js';
import { CUSTOMER_PII_KEY_ALT_NAME } from './customerEncryptionSchema.js';

const log = childLogger('key-vault');

export function vaultProviders() {
  return { local: { key: readFileSync(config.keyVault.localMasterKeyFile) } };
}

/**
 * @param {import('mongodb').MongoClient} client
 * @returns {Promise<import('mongodb').UUID>}
 */
export async function ensureCustomerDataKey(client) {
  const vault = new ClientEncryption(client, {
    keyVaultNamespace: config.keyVault.namespace,
    kmsProviders: vaultProviders(),
  });
  const existing = await vault.getKeyByAltName(CUSTOMER_PII_KEY_ALT_NAME);
  if (existing) return existing._id;
  const dataKeyId = await vault.createDataKey('local', { keyAltNames: [CUSTOMER_PII_KEY_ALT_NAME] });
  log.info({ keyAltName: CUSTOMER_PII_KEY_ALT_NAME }, 'created customer data key');
  return dataKeyId;
}
