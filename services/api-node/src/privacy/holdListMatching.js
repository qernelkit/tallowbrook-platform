// Do-not-deliver list check for the driver app. The app asks whether a consignee is on
// the list without the gateway learning who it asked about; the gateway evaluates the
// app's masked query with the list key and the app compares the result locally.
import { ristretto255_oprf } from '@noble/curves/ed25519.js';
import { secret } from '../config.js';

const ELEMENT_HEX = /^[0-9a-f]{64}$/;
const QUERIES_PER_HOUR = 600;

/** @type {Map<string, { windowStart: number, count: number }>} */
const usage = new Map();

/**
 * @param {string} driverId
 * @param {number} now
 */
export function withinQuota(driverId, now = Date.now()) {
  const entry = usage.get(driverId);
  if (!entry || now - entry.windowStart > 3_600_000) {
    usage.set(driverId, { windowStart: now, count: 1 });
    return true;
  }
  entry.count += 1;
  return entry.count <= QUERIES_PER_HOUR;
}

/**
 * @param {string} queryHex 32-byte group element from the driver app
 * @returns {string} evaluated element, hex
 */
export function evaluateHoldListQuery(queryHex) {
  if (!ELEMENT_HEX.test(queryHex)) throw new Error('query must be a 32-byte element');
  const listKey = Buffer.from(secret('HOLD_LIST_KEY'), 'hex');
  const blinded = Buffer.from(queryHex, 'hex');
  return Buffer.from(ristretto255_oprf.oprf.blindEvaluate(listKey, blinded)).toString('hex');
}
