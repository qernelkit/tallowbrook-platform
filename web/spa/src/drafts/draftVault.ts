// Offline booking drafts. Drafts are sealed with the PIN-derived key and kept in
// localStorage until the shipper is back online and submits them.
import type { BookingDraft } from '../api/types';
import { DraftCipher } from '../crypto/algorithms';
import { base64ToBytes, bytesToBase64, utf8 } from '../crypto/bytes';

const PREFIX = 'tb.draft.';
const MAX_DRAFTS = 20;

interface SealedDraft {
  v: 1;
  iv: string;
  body: string;
  savedAt: string;
}

export async function sealDraft(key: CryptoKey, draft: BookingDraft): Promise<SealedDraft> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const sealed = await crypto.subtle.encrypt({ name: DraftCipher.Name as string, iv }, key, utf8(JSON.stringify(draft)));
  return { v: 1, iv: bytesToBase64(iv), body: bytesToBase64(new Uint8Array(sealed)), savedAt: new Date().toISOString() };
}

export async function openDraft(key: CryptoKey, sealed: SealedDraft): Promise<BookingDraft> {
  const iv = base64ToBytes(sealed.iv);
  const plain = await crypto.subtle.decrypt({ name: DraftCipher.Name as string, iv }, key, base64ToBytes(sealed.body));
  return JSON.parse(new TextDecoder().decode(plain)) as BookingDraft;
}

export function listDraftIds(): string[] {
  const ids: string[] = [];
  for (let i = 0; i < localStorage.length; i += 1) {
    const name = localStorage.key(i);
    if (name?.startsWith(PREFIX)) ids.push(name.slice(PREFIX.length));
  }
  return ids.sort();
}

export async function saveDraft(key: CryptoKey, id: string, draft: BookingDraft): Promise<void> {
  if (!listDraftIds().includes(id) && listDraftIds().length >= MAX_DRAFTS) {
    throw new Error(`At most ${MAX_DRAFTS} drafts can be kept offline`);
  }
  localStorage.setItem(PREFIX + id, JSON.stringify(await sealDraft(key, draft)));
}

export async function loadDraft(key: CryptoKey, id: string): Promise<BookingDraft | null> {
  const raw = localStorage.getItem(PREFIX + id);
  if (!raw) return null;
  return openDraft(key, JSON.parse(raw) as SealedDraft);
}

export function deleteDraft(id: string): void {
  localStorage.removeItem(PREFIX + id);
}
