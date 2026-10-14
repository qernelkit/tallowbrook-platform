// Short-lived session tokens for the shipper web app. The app keeps them in memory
// and trades them for a fresh one before expiry.
import jwt from 'jsonwebtoken';
import { config, secret } from '../config.js';
import { unauthorized } from '../middleware/errors.js';

const SESSION_TTL = config.session.tokenTtl;

/**
 * @param {string} sid server-side session id
 * @param {string} sub account id
 * @returns {string}
 */
export function issueSessionToken(sid, sub) {
  return jwt.sign({ sid, sub }, secret('SESSION_TOKEN_SECRET'), { expiresIn: SESSION_TTL });
}

/**
 * @param {string} token
 * @returns {{ sid: string, sub: string }}
 */
export function readSessionToken(token) {
  const claims = jwt.verify(token, secret('SESSION_TOKEN_SECRET'));
  if (typeof claims === 'string' || typeof claims.sid !== 'string' || typeof claims.sub !== 'string') {
    throw unauthorized('session_token_malformed');
  }
  return { sid: claims.sid, sub: claims.sub };
}

/**
 * Express middleware: reads "Authorization: Session <token>" when present.
 * @type {import('express').RequestHandler}
 */
export function sessionTokenAuth(req, res, next) {
  const header = req.get('authorization') ?? '';
  const [scheme, value] = header.split(' ');
  if (scheme !== 'Session' || !value) {
    next(unauthorized());
    return;
  }
  try {
    res.locals.session = readSessionToken(value);
    next();
  } catch {
    next(unauthorized('session_token_invalid'));
  }
}
