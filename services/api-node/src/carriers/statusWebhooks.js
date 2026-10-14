// Status webhooks from Ridgeway and Kestrel. Both send X-Carrier-Signature as
// "sha1=<hex>", an HMAC over the raw body with the secret set up at onboarding.
import { createHmac, timingSafeEqual } from 'node:crypto';

const HEADER_PREFIX = 'sha1=';

const STATUS_MAP = {
  PU: 'collected',
  IT: 'in_transit',
  OD: 'out_for_delivery',
  DL: 'delivered',
  EX: 'exception',
  RT: 'returned',
};

/**
 * @param {{ webhookSecret: string }} carrier
 * @param {Buffer} rawBody
 * @param {string | undefined} header
 */
export function statusSignatureValid(carrier, rawBody, header) {
  if (!header || !header.startsWith(HEADER_PREFIX)) return false;
  const given = Buffer.from(header.slice(HEADER_PREFIX.length), 'hex');
  const expected = createHmac('sha1', carrier.webhookSecret).update(rawBody).digest('hex');
  const wanted = Buffer.from(expected, 'hex');
  return given.length === wanted.length && timingSafeEqual(given, wanted);
}

/**
 * @param {any} payload
 */
export function normaliseStatus(payload) {
  const code = String(payload?.status_code ?? '').toUpperCase();
  const status = STATUS_MAP[code];
  if (!status) return null;
  return {
    trackingNumber: String(payload.awb ?? '')
      .trim()
      .toUpperCase(),
    status,
    at: new Date(payload.event_time ?? Date.now()),
    depot: payload.depot_code ?? null,
    signedBy: payload.pod_name ?? null,
  };
}
