// Drivers show a training credential (forklift, ADR dangerous goods) issued by the
// training provider as a W3C verifiable credential. The shipper's dock staff check it
// in the browser before loading.
import { sha256 } from '@noble/hashes/sha2.js';
import { concatBytes } from '@noble/hashes/utils.js';
import type { TrainingCredential } from '../api/types';
import { base58ToBytes, utf8 } from '../crypto/bytes';

const ACCEPTED_PROOF_TYPE = 'Ed25519Signature2020';
const MULTIKEY_PREFIX = [0xed, 0x01];

export type CredentialVerdict = 'valid' | 'invalid' | 'expired' | 'unsupported';

function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object') {
    const entries = Object.entries(value as Record<string, unknown>).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
    return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonical(v)}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

// did:key:z6Mk… → raw 32-byte issuer key
export function issuerKeyFromDid(did: string): Uint8Array<ArrayBuffer> {
  const match = /^did:key:z([1-9A-HJ-NP-Za-km-z]+)$/.exec(did.split('#')[0]);
  if (!match) throw new Error('issuer is not a did:key');
  const decoded = base58ToBytes(match[1]);
  if (decoded[0] !== MULTIKEY_PREFIX[0] || decoded[1] !== MULTIKEY_PREFIX[1] || decoded.length !== 34) {
    throw new Error('issuer key is not the expected key type');
  }
  return decoded.slice(2);
}

export async function verifyTrainingCredential(vc: TrainingCredential, now = new Date()): Promise<CredentialVerdict> {
  const { proof, ...document } = vc;
  if (proof.type !== ACCEPTED_PROOF_TYPE) return 'unsupported';
  if (vc.expirationDate && new Date(vc.expirationDate) < now) return 'expired';
  const { proofValue, ...proofConfig } = proof;
  const proofConfigBytes = utf8(canonical({ ...proofConfig, '@context': vc['@context'] }));
  const documentBytes = utf8(canonical(document));
  const signedBytes = concatBytes(sha256(proofConfigBytes), sha256(documentBytes));
  const issuerKeyBytes = issuerKeyFromDid(proof.verificationMethod);
  const issuerKey = await crypto.subtle.importKey('raw', issuerKeyBytes, 'Ed25519', false, ['verify']);
  const ok = await crypto.subtle.verify('Ed25519', issuerKey, base58ToBytes(proofValue.slice(1)), signedBytes);
  return ok ? 'valid' : 'invalid';
}
