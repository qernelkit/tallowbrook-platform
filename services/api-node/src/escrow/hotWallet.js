// Settlement batches for treasury are signed by the escrow hot wallet. Treasury checks
// the signature against the wallet's public key before it pays out.
import { createPrivateKey } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { config } from '../config.js';
import { canonicalJson } from '../receipts/receiptSigner.js';

/** @type {Uint8Array | undefined} */
let walletScalar;

function loadHotWalletKey() {
  const jwk = createPrivateKey(readFileSync(config.escrow.hotWalletKeyFile, 'utf8')).export({ format: 'jwk' });
  return new Uint8Array(Buffer.from(jwk.d, 'base64url'));
}

/**
 * @param {{ batchId: string, payouts: { courier: string, amountWei: string }[] }} batch
 * @returns {string} hex compact signature
 */
export function signSettlementBatch(batch) {
  if (batch.payouts.length === 0) throw new Error('empty settlement batch');
  const batchBytes = new TextEncoder().encode(canonicalJson(batch));
  const hotWalletKey = (walletScalar ??= loadHotWalletKey());
  const signature = secp256k1.sign(batchBytes, hotWalletKey);
  return Buffer.from(signature).toString('hex');
}
