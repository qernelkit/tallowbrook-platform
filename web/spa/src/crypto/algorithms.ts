// Every algorithm choice the app makes lives here; feature modules import from this
// file instead of naming algorithms themselves.

// Offline booking drafts and the local cache.
export enum DraftCipher {
  Name = 'AES-GCM',
  KeyBits = 256,
}

// Offline PIN to draft key.
export const PIN_KDF = { name: 'PBKDF2', hash: 'SHA-256', iterations: 600_000 } as const;

// Customs receipts are signed by the authority's receipt service.
export const RECEIPT_SIGNATURE = { name: 'RSA-PSS', saltLength: 32 } as const;

// End-to-end shared delivery notes.
export const SHARE_LINK_CURVE = 'P-384';

// The object store wants this checksum on direct uploads.
export const UPLOAD_CHECKSUM = 'SHA-1';
