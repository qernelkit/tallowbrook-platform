// Six-digit driver PINs for the handheld login. Cost 11 keeps a login under 300 ms on
// the depot terminals, which is the limit drivers tolerate at shift start.
import * as bcrypt from 'bcrypt';

const PIN_HASH_ROUNDS = 11;
const PIN_FORMAT = /^\d{6}$/;
const WEAK_PINS = new Set(['000000', '111111', '123456', '654321', '121212', '112233']);

/**
 * @param {string} pin
 * @returns {string | null} why the PIN is refused, or null
 */
export function pinProblem(pin) {
  if (!PIN_FORMAT.test(pin)) return 'PIN must be six digits';
  if (WEAK_PINS.has(pin)) return 'PIN is too easy to guess';
  return null;
}

/**
 * @param {string} pin
 */
export function hashDriverPin(pin) {
  return bcrypt.hash(pin, PIN_HASH_ROUNDS);
}

/**
 * @param {string} pin
 * @param {string} stored
 */
export function checkDriverPin(pin, stored) {
  if (!PIN_FORMAT.test(pin)) return Promise.resolve(false);
  return bcrypt.compare(pin, stored);
}
