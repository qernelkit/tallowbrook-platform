// Assertions we send to partners, and the partner tokens we accept on /partners.
import { readFileSync } from 'node:fs';
import { SignJWT, createRemoteJWKSet, importPKCS8, jwtVerify } from 'jose';
import { config } from '../config.js';
import { PARTNER_ASSERTION_TTL, PARTNER_JWS_ALG } from './algorithms.js';

const PARTNER_KID = 'tb-partners-2026';

const partnerJwks = createRemoteJWKSet(new URL(config.partners.jwksUrl));

/** @type {ReturnType<typeof importPKCS8> | undefined} */
let assertionKey;

function partnerAssertionKey() {
  assertionKey ??= importPKCS8(readFileSync(config.partners.signingKeyFile, 'utf8'), PARTNER_JWS_ALG);
  return assertionKey;
}

/**
 * @param {string} partnerId audience, as registered with the partner
 * @param {Record<string, unknown>} claims
 * @returns {Promise<string>}
 */
export async function signPartnerAssertion(partnerId, claims) {
  return new SignJWT(claims)
    .setProtectedHeader({ alg: PARTNER_JWS_ALG, kid: PARTNER_KID })
    .setIssuer(config.partners.issuer)
    .setAudience(partnerId)
    .setIssuedAt()
    .setExpirationTime(PARTNER_ASSERTION_TTL)
    .sign(await partnerAssertionKey());
}

/**
 * @param {string} token
 * @returns {Promise<{ partnerId: string, scopes: string[] }>}
 */
export async function verifyPartnerToken(token) {
  const { payload } = await jwtVerify(token, partnerJwks, {
    algorithms: config.partners.acceptedAlgorithms,
    issuer: config.partners.trustedIssuers,
    audience: config.partners.issuer,
    clockTolerance: 30,
  });
  if (typeof payload.sub !== 'string') throw new Error('partner token has no subject');
  return {
    partnerId: payload.sub,
    scopes: typeof payload.scope === 'string' ? payload.scope.split(' ') : [],
  };
}
