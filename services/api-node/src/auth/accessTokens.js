// Service tokens for calls from the gateway to internal services, and the check for
// tokens those services send back.
import { readFileSync } from 'node:fs';
import jwt from 'jsonwebtoken';
import { config } from '../config.js';
import { ACCESS_TOKEN_ALGORITHMS } from './algorithms.js';
import { ACCESS_KEY_ID, ACCESS_TOKEN_PUBLIC_KEY } from './issuerKeys.js';

const KNOWN_AUDIENCES = new Set(['payments', 'ledger', 'reporting', 'notify']);

/** @type {string | undefined} */
let issuerKeyPem;

function issuerKey() {
  issuerKeyPem ??= readFileSync(config.tokens.signingKeyFile, 'utf8');
  return issuerKeyPem;
}

/**
 * @param {string} audience
 * @param {string[]} scopes
 * @returns {string}
 */
export function issueAccessToken(audience, scopes) {
  if (!KNOWN_AUDIENCES.has(audience)) throw new Error(`no access tokens for ${audience}`);
  return jwt.sign({ scope: scopes.join(' ') }, issuerKey(), {
    algorithm: 'ES256',
    expiresIn: config.tokens.ttl,
    issuer: config.tokens.issuer,
    audience,
    keyid: ACCESS_KEY_ID,
  });
}

/**
 * @param {string} token
 * @param {string} audience
 */
export function verifyAccessToken(token, audience) {
  return jwt.verify(token, ACCESS_TOKEN_PUBLIC_KEY, { algorithms: ACCESS_TOKEN_ALGORITHMS, audience });
}

/**
 * @param {string | jwt.JwtPayload} claims
 * @param {string} needed
 */
export function hasScope(claims, needed) {
  if (typeof claims === 'string') return false;
  const scopes = typeof claims.scope === 'string' ? claims.scope.split(' ') : [];
  return scopes.includes(needed);
}
