// The browser's device key binds sessions to this browser (DPoP). It is created
// non-extractable and kept in IndexedDB, so script on the page can use it but nobody
// can copy it out.

const DB_NAME = 'tallowbrook-device';
const STORE = 'keys';
const KEY_ID = 'device';

function openDeviceDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, 1);
    request.onupgradeneeded = () => request.result.createObjectStore(STORE);
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

function readStored(db: IDBDatabase): Promise<CryptoKeyPair | undefined> {
  return new Promise((resolve, reject) => {
    const request = db.transaction(STORE, 'readonly').objectStore(STORE).get(KEY_ID);
    request.onsuccess = () => resolve(request.result as CryptoKeyPair | undefined);
    request.onerror = () => reject(request.error);
  });
}

function writeStored(db: IDBDatabase, pair: CryptoKeyPair): Promise<void> {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, 'readwrite');
    tx.objectStore(STORE).put(pair, KEY_ID);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

let pending: Promise<CryptoKeyPair> | null = null;

async function loadOrCreate(): Promise<CryptoKeyPair> {
  const db = await openDeviceDb();
  const stored = await readStored(db);
  if (stored) return stored;
  const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']);
  await writeStored(db, pair);
  return pair;
}

export function deviceKey(): Promise<CryptoKeyPair> {
  pending ??= loadOrCreate().catch((err: unknown) => {
    pending = null;
    throw err;
  });
  return pending;
}

export async function forgetDeviceKey(): Promise<void> {
  const db = await openDeviceDb();
  await new Promise<void>((resolve, reject) => {
    const tx = db.transaction(STORE, 'readwrite');
    tx.objectStore(STORE).delete(KEY_ID);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
  pending = null;
}
