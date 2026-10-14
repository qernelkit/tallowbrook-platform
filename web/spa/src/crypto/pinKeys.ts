// Offline booking drafts are protected by a short PIN the shipper picks, so drafts on a
// shared depot PC are not readable by the next person.
import { DraftCipher, PIN_KDF } from './algorithms';
import { utf8 } from './bytes';

// Fixed per app build so the same PIN opens drafts saved before an update.
const DRAFTS_SALT = new Uint8Array([0x5e, 0x91, 0xbc, 0xde, 0x18, 0x22, 0x6d, 0x93, 0x4f, 0xef, 0x6f, 0xc6, 0x4c, 0x06, 0x16, 0x81]);

export function pinIsAcceptable(pin: string): boolean {
  return /^\d{6,10}$/.test(pin) && new Set(pin).size > 2;
}

export async function draftKeyFromPin(pin: string): Promise<CryptoKey> {
  if (!pinIsAcceptable(pin)) throw new Error('PIN must be 6 to 10 digits');
  const pinKey = await crypto.subtle.importKey('raw', utf8(pin), PIN_KDF.name, false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ ...PIN_KDF, salt: DRAFTS_SALT }, pinKey, DraftCipher.KeyBits);
  return crypto.subtle.importKey('raw', bits, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}
