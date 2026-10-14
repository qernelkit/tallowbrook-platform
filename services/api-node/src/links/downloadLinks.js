// Signed, expiring links for shipping label PDFs. Labels are fetched by label
// printers that cannot send our auth headers, so the link itself carries the grant.
import { createHmac, timingSafeEqual } from 'node:crypto';
import { config, secret } from '../config.js';

const LINK_SIGNATURE_DIGEST = 'sha256';

/**
 * @param {string} path
 * @param {number} expires unix seconds
 */
function linkSignature(path, expires) {
  return createHmac(LINK_SIGNATURE_DIGEST, secret('DOWNLOAD_LINK_KEY')).update(`${path}:${expires}`).digest('base64url');
}

/**
 * @param {string} shipmentId
 * @param {'a6' | '4x6'} format
 * @param {number} [now] ms
 */
export function signedLabelUrl(shipmentId, format, now = Date.now()) {
  const path = `/v1/labels/${encodeURIComponent(shipmentId)}.${format}.pdf`;
  const expires = Math.floor(now / 1000) + config.links.lifetimeSeconds;
  const url = new URL(path, config.publicBaseUrl);
  url.searchParams.set('expires', String(expires));
  url.searchParams.set('sig', linkSignature(path, expires));
  return url.toString();
}

/**
 * @param {string} path
 * @param {string | undefined} expires
 * @param {string | undefined} sig
 * @param {number} [now] ms
 * @returns {'ok' | 'expired' | 'invalid'}
 */
export function checkLabelLink(path, expires, sig, now = Date.now()) {
  const expiresAt = Number(expires);
  if (!Number.isInteger(expiresAt) || !sig) return 'invalid';
  const given = Buffer.from(sig, 'base64url');
  const wanted = Buffer.from(linkSignature(path, expiresAt), 'base64url');
  if (given.length !== wanted.length || !timingSafeEqual(given, wanted)) return 'invalid';
  return expiresAt * 1000 < now ? 'expired' : 'ok';
}
