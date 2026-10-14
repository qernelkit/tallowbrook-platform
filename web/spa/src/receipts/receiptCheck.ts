// Customs receipts can be checked in the browser against the authority's published
// key, so a shipper can trust a forwarded PDF without calling us.
import type { CustomsReceipt } from '../api/types';
import { RECEIPT_SIGNATURE } from '../crypto/algorithms';
import { base64ToBytes, base64UrlToBytes, utf8 } from '../crypto/bytes';

export type ReceiptVerdict = 'valid' | 'invalid' | 'expired-key';

async function authorityKey(spkiB64: string): Promise<CryptoKey> {
  return crypto.subtle.importKey('spki', base64ToBytes(spkiB64), { name: RECEIPT_SIGNATURE.name, hash: 'SHA-256' }, false, ['verify']);
}

function signedBody(receipt: CustomsReceipt): Uint8Array<ArrayBuffer> {
  const { signature: _ignored, ...fields } = receipt;
  const keys = Object.keys(fields).sort() as (keyof typeof fields)[];
  return utf8(JSON.stringify(Object.fromEntries(keys.map((k) => [k, fields[k]]))));
}

export async function checkCustomsReceipt(
  receipt: CustomsReceipt,
  authority: { spki: string; validUntil: string },
): Promise<ReceiptVerdict> {
  if (new Date(receipt.issuedAt) > new Date(authority.validUntil)) return 'expired-key';
  const receiptKey = await authorityKey(authority.spki);
  const ok = await crypto.subtle.verify(RECEIPT_SIGNATURE, receiptKey, base64UrlToBytes(receipt.signature), signedBody(receipt));
  return ok ? 'valid' : 'invalid';
}
