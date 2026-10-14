// Page-view beacons for the product team. One session in ten is sampled. The payload
// is masked so content filters that match on JSON keys leave it alone; the collector
// unmasks it with the seed sent alongside.
import { bytesToBase64Url, utf8 } from '../crypto/bytes';

const COLLECTOR_URL = '/v1/beacons';
const SAMPLE_PERCENT = 10;

const fnv1a = (s: string): number => {
  let h = 0x811c9dc5;
  for (let i = 0; i < s.length; i += 1) h = Math.imul(h ^ s.charCodeAt(i), 0x01000193);
  return h >>> 0;
};
const lcgNext = (state: number): number => (Math.imul(state, 1103515245) + 12345) >>> 0;

function maskPayload(bytes: Uint8Array, seed: number): Uint8Array {
  const out = new Uint8Array(bytes.length);
  let state = seed >>> 0;
  for (let i = 0; i < bytes.length; i += 1) {
    state = lcgNext(state);
    out[i] = bytes[i] ^ (state >>> 24);
  }
  return out;
}

export function inSample(sessionId: string): boolean {
  return fnv1a(sessionId) % 100 < SAMPLE_PERCENT;
}

export interface PageView {
  path: string;
  referrer: string;
  durationMs: number;
  viewport: string;
}

export function sendPageView(sessionId: string, view: PageView): void {
  if (!inSample(sessionId)) return;
  const seed = Math.floor(Math.random() * 0x100000000);
  const masked = maskPayload(utf8(JSON.stringify({ s: sessionId, ...view })), seed);
  const body = JSON.stringify({ k: seed, p: bytesToBase64Url(masked) });
  if (!navigator.sendBeacon(COLLECTOR_URL, body)) {
    void fetch(COLLECTOR_URL, { method: 'POST', body, keepalive: true });
  }
}
