// End-to-end shared delivery notes ("leave it with the neighbour at no. 12, gate code
// 4471"). The note is encrypted in the browser to the recipient's published share key,
// so the gateway only stores ciphertext.
import { postJson } from '../api/client';
import { SHARE_LINK_CURVE } from '../crypto/algorithms';
import { bytesToBase64Url, utf8 } from '../crypto/bytes';

const SHARE_LINK_INFO = utf8('tb-share-link/v1');

export interface SharedNote {
  ephemeral: string;
  salt: string;
  iv: string;
  body: string;
}

export async function importRecipientShareKey(jwk: JsonWebKey): Promise<CryptoKey> {
  return crypto.subtle.importKey('jwk', jwk, { name: 'ECDH', namedCurve: SHARE_LINK_CURVE }, false, []);
}

export async function encryptNoteFor(recipientKey: CryptoKey, note: string): Promise<SharedNote> {
  const ephemeral = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: SHARE_LINK_CURVE }, false, ['deriveBits']);
  const secret = await crypto.subtle.deriveBits({ name: 'ECDH', public: recipientKey }, ephemeral.privateKey, 384);
  const linkSalt = crypto.getRandomValues(new Uint8Array(32));
  const ikm = await crypto.subtle.importKey('raw', secret, 'HKDF', false, ['deriveKey']);
  const linkKey = await crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: linkSalt, info: SHARE_LINK_INFO },
    ikm,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt'],
  );
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const body = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, linkKey, utf8(note));
  const raw = await crypto.subtle.exportKey('raw', ephemeral.publicKey);
  return {
    ephemeral: bytesToBase64Url(new Uint8Array(raw)),
    salt: bytesToBase64Url(linkSalt),
    iv: bytesToBase64Url(iv),
    body: bytesToBase64Url(new Uint8Array(body)),
  };
}

export async function shareDeliveryNote(shipmentId: string, recipientKeyJwk: JsonWebKey, note: string): Promise<string> {
  if (note.trim().length === 0) throw new Error('Write a note first');
  if (note.length > 1000) throw new Error('Notes are limited to 1000 characters');
  const sealed = await encryptNoteFor(await importRecipientShareKey(recipientKeyJwk), note);
  const { url } = await postJson<{ url: string }>(`/v1/shipments/${shipmentId}/shared-notes`, sealed);
  return url;
}
