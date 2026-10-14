#!/usr/bin/env node
// Ops script: generates a new field master key and re-seals every sealed field.
//
//   FIELD_MASTER_KEY=<current, base64> node scripts/rotate-field-master-key.mjs <out-file>
//
// The new key is written to <out-file> (mode 0600) for the operator to load into the
// secret store; the gateway picks it up on the next deploy.
import { generateKeySync } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { MongoClient } from 'mongodb';
import { config, secretBytes } from '../src/config.js';
import { isSealedField, openField, sealField } from '../src/crypto/fieldCipher.js';

const SEALED_COLLECTIONS = {
  shipments: ['deliveryNote'],
  claims: ['description'],
  driverDevices: ['vaultKey'],
  tenantApiKeys: ['privatePem'],
};

async function main() {
  const outFile = process.argv[2];
  if (!outFile) {
    console.error('usage: rotate-field-master-key.mjs <out-file>');
    process.exit(2);
  }
  const current = secretBytes('FIELD_MASTER_KEY');
  const next = generateKeySync('aes', { length: 256 });
  const nextKey = next.export();
  writeFileSync(outFile, nextKey.toString('base64') + '\n', { mode: 0o600 });

  const client = await MongoClient.connect(config.mongo.uri);
  try {
    const db = client.db(config.mongo.database);
    const tenants = new Map();
    for await (const tenant of db.collection('tenants').find({}, { projection: { _id: 1, fieldSalt: 1 } })) {
      tenants.set(String(tenant._id), { id: String(tenant._id), fieldSalt: Buffer.from(tenant.fieldSalt.buffer) });
    }
    let resealed = 0;
    for (const [name, fields] of Object.entries(SEALED_COLLECTIONS)) {
      for await (const doc of db
        .collection(name)
        .find({}, { projection: { tenantId: 1, ...Object.fromEntries(fields.map((f) => [f, 1])) } })) {
        const tenant = tenants.get(String(doc.tenantId));
        if (!tenant) continue;
        const update = {};
        for (const field of fields) {
          if (!isSealedField(doc[field])) continue;
          update[field] = sealField(tenant, openField(tenant, doc[field], current), nextKey);
        }
        if (Object.keys(update).length === 0) continue;
        await db.collection(name).updateOne({ _id: doc._id }, { $set: update });
        resealed += 1;
      }
      console.log(`${name}: done`);
    }
    console.log(`resealed ${resealed} documents; load ${outFile} into the secret store before the next deploy`);
  } finally {
    await client.close();
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
