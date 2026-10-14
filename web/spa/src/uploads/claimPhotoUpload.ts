// Damage-claim photos go straight from the browser to object storage with a one-time
// upload URL from the gateway. The storage API rejects a PUT without a checksum header.
import { postJson } from '../api/client';
import { UPLOAD_CHECKSUM } from '../crypto/algorithms';
import { bytesToHex } from '../crypto/bytes';

const MAX_BYTES = 15 * 1024 * 1024;
const ACCEPTED = ['image/jpeg', 'image/png', 'image/heic'];

export interface UploadTarget {
  objectKey: string;
  uploadUrl: string;
}

export function photoProblem(file: File): string | null {
  if (!ACCEPTED.includes(file.type)) return 'Photos must be JPEG, PNG or HEIC';
  if (file.size > MAX_BYTES) return 'Photos must be under 15 MB';
  return null;
}

export async function uploadClaimPhoto(claimId: string, file: File): Promise<string> {
  const problem = photoProblem(file);
  if (problem) throw new Error(problem);
  const target = await postJson<UploadTarget>(`/v1/claims/${claimId}/photos`, { contentType: file.type, size: file.size });
  const bytes = new Uint8Array(await file.arrayBuffer());
  const checksum = await crypto.subtle.digest(UPLOAD_CHECKSUM, bytes);
  const response = await fetch(target.uploadUrl, {
    method: 'PUT',
    headers: { 'Content-Type': file.type, 'X-Content-Sha1': bytesToHex(new Uint8Array(checksum)) },
    body: bytes,
  });
  if (!response.ok) throw new Error(`Upload failed (${response.status})`);
  return target.objectKey;
}
