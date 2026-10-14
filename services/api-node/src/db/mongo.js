import { MongoClient } from 'mongodb';
import { config } from '../config.js';
import { customerSchemaMap } from './customerEncryptionSchema.js';
import { ensureCustomerDataKey, vaultProviders } from './keyVault.js';

/**
 * Connects twice: once without auto-encryption to find (or create) the data key, then
 * with the schema map that uses it.
 * @returns {Promise<import('mongodb').Db>}
 */
export async function connectMongo() {
  const setup = await MongoClient.connect(config.mongo.uri);
  let dataKeyId;
  try {
    dataKeyId = await ensureCustomerDataKey(setup);
  } finally {
    await setup.close();
  }
  const client = new MongoClient(config.mongo.uri, {
    autoEncryption: {
      keyVaultNamespace: config.keyVault.namespace,
      kmsProviders: vaultProviders(),
      schemaMap: customerSchemaMap(dataKeyId),
    },
    appName: config.service,
    maxPoolSize: 50,
  });
  await client.connect();
  return client.db(config.mongo.database);
}
