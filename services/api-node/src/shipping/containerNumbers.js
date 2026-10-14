// ISO 6346 container numbers: owner code (3 letters), category (U, J or Z), six
// digits and a check digit, e.g. CSQU3054383.

const LETTER_VALUES = (() => {
  const values = new Map();
  let value = 10;
  for (const letter of 'ABCDEFGHIJKLMNOPQRSTUVWXYZ') {
    if (value % 11 === 0) value += 1;
    values.set(letter, value);
    value += 1;
  }
  return values;
})();

/**
 * @param {string} raw
 */
export function normaliseContainerNumber(raw) {
  return raw.replace(/[\s-]/g, '').toUpperCase();
}

/**
 * @param {string} first10 owner code, category and serial
 * @returns {number}
 */
export function checkDigit(first10) {
  let weightedSum = 0;
  for (let i = 0; i < 10; i += 1) {
    const ch = first10[i];
    const value = /\d/.test(ch) ? Number(ch) : LETTER_VALUES.get(ch);
    weightedSum += value * 2 ** i;
  }
  const checksum = (weightedSum % 11) % 10;
  return checksum;
}

/**
 * @param {string} raw
 */
export function isValidContainerNumber(raw) {
  const number = normaliseContainerNumber(raw);
  if (!/^[A-Z]{3}[UJZ]\d{7}$/.test(number)) return false;
  return checkDigit(number.slice(0, 10)) === Number(number[10]);
}
