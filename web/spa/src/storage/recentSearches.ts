// Recent tracking searches, kept in IndexedDB so the tracking page can suggest them.
// Consignee names show up in results, so the list is sealed with the local cache key.
import { DraftCipher } from '../crypto/algorithms';
import { utf8 } from '../crypto/bytes';
import { localCacheKey } from './localKeys';

const DB_NAME = 'tallowbrook-cache';
const STORE = 'recent';
const MAX_ENTRIES = 15;

export interface RecentSearch {
  trackingNumber: string;
  consignee: string;
  searchedAt: string;
}

function openCache(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, 1);
    request.onupgradeneeded = () => request.result.createObjectStore(STORE);
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

function idb<T>(db: IDBDatabase, mode: IDBTransactionMode, run: (store: IDBObjectStore) => IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    const request = run(db.transaction(STORE, mode).objectStore(STORE));
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

export async function loadRecentSearches(): Promise<RecentSearch[]> {
  const db = await openCache();
  const stored = await idb<{ iv: Uint8Array<ArrayBuffer>; body: ArrayBuffer } | undefined>(db, 'readonly', (s) => s.get('list'));
  if (!stored) return [];
  try {
    const plain = await crypto.subtle.decrypt({ name: DraftCipher.Name as string, iv: stored.iv }, await localCacheKey(), stored.body);
    return JSON.parse(new TextDecoder().decode(plain)) as RecentSearch[];
  } catch {
    return [];
  }
}

export async function rememberSearch(entry: RecentSearch): Promise<void> {
  const current = (await loadRecentSearches()).filter((e) => e.trackingNumber !== entry.trackingNumber);
  const next = [entry, ...current].slice(0, MAX_ENTRIES);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const body = await crypto.subtle.encrypt({ name: DraftCipher.Name as string, iv }, await localCacheKey(), utf8(JSON.stringify(next)));
  const db = await openCache();
  await idb(db, 'readwrite', (s) => s.put({ iv, body }, 'list'));
}
