// Public order ids: short, unambiguous strings for order numbers that customers read
// out on the phone. They are not secret; support can decode them.
import Hashids from 'hashids';
import { config } from '../config.js';

const ALPHABET = 'abcdefghjkmnpqrstuvwxyz23456789';

const hashids = new Hashids(config.publicIds.salt, config.publicIds.length, ALPHABET);

/**
 * @param {number} orderNumber
 */
export function publicOrderId(orderNumber) {
  return hashids.encode(orderNumber);
}

/**
 * @param {string} publicId
 * @returns {number | null}
 */
export function orderNumberFromPublicId(publicId) {
  const [orderNumber] = hashids.decode(publicId);
  return typeof orderNumber === 'number' ? orderNumber : orderNumber === undefined ? null : Number(orderNumber);
}
