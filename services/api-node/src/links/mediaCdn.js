// Proof-of-delivery photos are served by the media CDN, which only accepts canned
// policy URLs signed with the key registered in its console.
import { createPrivateKey, createSign } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { config } from '../config.js';

export const MEDIA_CDN = {
  baseUrl: config.links.mediaBaseUrl,
  keyId: config.links.cdnKeyId,
  signatureAlgorithm: 'RSA-SHA1',
  defaultLifetimeSeconds: 3600,
};

/** @type {import('node:crypto').KeyObject | undefined} */
let urlKey;

function cdnUrlKey() {
  urlKey ??= createPrivateKey(readFileSync(config.links.cdnKeyFile, 'utf8'));
  return urlKey;
}

/**
 * The CDN wants base64 with + = / replaced by - _ ~.
 * @param {string} b64
 */
function cdnSafe(b64) {
  return b64.replace(/\+/g, '-').replace(/=/g, '_').replace(/\//g, '~');
}

/**
 * @param {string} objectKey e.g. pod/2026/10/14/shp_123/front.jpg
 * @param {number} [now] ms
 */
export function signedPhotoUrl(objectKey, now = Date.now()) {
  if (objectKey.includes('..') || objectKey.startsWith('/')) throw new Error('bad media object key');
  const url = `${MEDIA_CDN.baseUrl}/${objectKey}`;
  const expires = Math.floor(now / 1000) + MEDIA_CDN.defaultLifetimeSeconds;
  const policy = JSON.stringify({ Statement: [{ Resource: url, Condition: { DateLessThan: { 'AWS:EpochTime': expires } } }] });
  const signer = createSign(MEDIA_CDN.signatureAlgorithm);
  signer.update(policy);
  const signature = signer.sign(cdnUrlKey(), 'base64');
  return `${url}?Expires=${expires}&Signature=${cdnSafe(signature)}&Key-Pair-Id=${MEDIA_CDN.keyId}`;
}
