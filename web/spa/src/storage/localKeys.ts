// The IndexedDB cache (tracking history, address book) is sealed with a key derived
// from a per-install secret, so a copied browser profile does not leak it in clear.
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { DraftCipher } from '../crypto/algorithms';
import { base64ToBytes, bytesToBase64, utf8 } from '../crypto/bytes';

const LOCAL_KEY_INFO = utf8('tb-local-cache/v1');
const INSTALL_ITEM = 'tb.install';

interface InstallMaterial {
  deviceSecret: string;
  installSalt: string;
}

function installMaterial(): InstallMaterial {
  const stored = localStorage.getItem(INSTALL_ITEM);
  if (stored) return JSON.parse(stored) as InstallMaterial;
  const fresh = {
    deviceSecret: bytesToBase64(crypto.getRandomValues(new Uint8Array(32))),
    installSalt: bytesToBase64(crypto.getRandomValues(new Uint8Array(16))),
  };
  localStorage.setItem(INSTALL_ITEM, JSON.stringify(fresh));
  return fresh;
}

export function localCacheKeyBytes(deviceSecret: Uint8Array, installSalt: Uint8Array): Uint8Array<ArrayBuffer> {
  return hkdf(sha256, deviceSecret, installSalt, LOCAL_KEY_INFO, 32);
}

export async function localCacheKey(): Promise<CryptoKey> {
  const { deviceSecret, installSalt } = installMaterial();
  const bytes = localCacheKeyBytes(base64ToBytes(deviceSecret), base64ToBytes(installSalt));
  return crypto.subtle.importKey('raw', bytes, { name: DraftCipher.Name as string }, false, ['encrypt', 'decrypt']);
}
