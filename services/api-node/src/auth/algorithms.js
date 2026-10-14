// JOSE algorithm choices shared by the token modules.

// Internal services sign with ES256; the ledger still sends RS256 until its HSM move.
/** @type {import('jsonwebtoken').Algorithm[]} */
export const ACCESS_TOKEN_ALGORITHMS = ['ES256', 'RS256'];

// Assertions we send to partners.
export const PARTNER_JWS_ALG = 'EdDSA';

export const PARTNER_ASSERTION_TTL = '5m';
