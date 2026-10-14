// Thin fetch wrapper for the gateway. The session token lives in memory only and is
// refreshed with a DPoP-bound call before it expires.
import { dpopProof } from '../auth/dpop';

export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    readonly details?: Record<string, string>,
  ) {
    super(`${status} ${code}`);
  }
}

let sessionToken: string | null = null;
let refreshTimer: number | undefined;

export function setSessionToken(token: string | null): void {
  sessionToken = token;
  window.clearTimeout(refreshTimer);
  if (token) refreshTimer = window.setTimeout(() => void refreshSession(), 10 * 60 * 1000);
}

async function request<T>(method: string, path: string, body?: unknown, extraHeaders: Record<string, string> = {}): Promise<T> {
  const headers: Record<string, string> = { Accept: 'application/json', ...extraHeaders };
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  if (sessionToken) headers.Authorization = `Session ${sessionToken}`;
  const response = await fetch(path, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
    credentials: 'include',
  });
  if (response.status === 204) return undefined as T;
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) throw new ApiError(response.status, payload.error ?? 'unknown', payload.details);
  return payload as T;
}

export const getJson = <T>(path: string) => request<T>('GET', path);
export const postJson = <T = void>(path: string, body: unknown) => request<T>('POST', path, body);
export const putJson = <T = void>(path: string, body: unknown) => request<T>('PUT', path, body);

export async function refreshSession(): Promise<void> {
  const url = new URL('/v1/account/session', window.location.origin).toString();
  const { token } = await request<{ token: string }>('POST', '/v1/account/session', {}, { DPoP: await dpopProof('POST', url) });
  setSessionToken(token);
}

export async function login(email: string, password: string): Promise<'done' | 'authenticator'> {
  const result = await request<{ token?: string; next?: string }>('POST', '/v1/account/login', { email, password });
  if (result.next === 'authenticator') return 'authenticator';
  setSessionToken(result.token ?? null);
  return 'done';
}

export async function submitAuthenticatorCode(code: string): Promise<void> {
  const { token } = await request<{ token: string }>('POST', '/v1/account/login/authenticator', { code });
  setSessionToken(token);
}
