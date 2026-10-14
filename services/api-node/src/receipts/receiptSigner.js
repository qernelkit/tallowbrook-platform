// Signed delivery receipts. The receipt key is created when a gateway pod starts; its
// public half goes to Mongo so receipts stay verifiable after the pod is gone.
import { generateKeyPairSync, randomUUID, sign } from 'node:crypto';
import { config } from '../config.js';
import { collection } from '../db/collections.js';

/** @type {{ keyId: string, pair: import('node:crypto').KeyPairKeyObjectResult } | undefined} */
let current;

function receiptKeys() {
  current ??= {
    keyId: `rk_${randomUUID()}`,
    pair: generateKeyPairSync('ec', { namedCurve: config.receipts.curve }),
  };
  return current;
}

/**
 * @param {unknown} value
 * @returns {string}
 */
export function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object') {
    const keys = Object.keys(value).sort();
    return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(value[k])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

/**
 * @param {import('mongodb').Db} db
 */
export async function publishReceiptKey(db) {
  const { keyId, pair } = receiptKeys();
  await collection(db, config.receipts.keysCollection).updateOne(
    { _id: keyId },
    { $setOnInsert: { jwk: pair.publicKey.export({ format: 'jwk' }), createdAt: new Date() } },
    { upsert: true },
  );
}

/**
 * @param {{ shipmentId: string, deliveredAt: string, receivedBy: string, depot: string }} receipt
 */
export function signDeliveryReceipt(receipt) {
  const receiptBytes = Buffer.from(canonicalJson(receipt), 'utf8');
  const { keyId, pair } = receiptKeys();
  const signature = sign('sha384', receiptBytes, pair.privateKey);
  return { ...receipt, keyId, signature: signature.toString('base64url') };
}
