import assert from 'node:assert/strict';
import { test } from 'node:test';
import { checkDigit, isValidContainerNumber, normaliseContainerNumber } from '../../src/shipping/containerNumbers.js';

test('accepts well-known container numbers', () => {
  for (const number of ['CSQU3054383', 'MSKU9070323', 'TGHU8796524']) {
    assert.equal(isValidContainerNumber(number), true, number);
  }
});

test('rejects a wrong check digit', () => {
  assert.equal(isValidContainerNumber('CSQU3054384'), false);
});

test('rejects the wrong shape', () => {
  assert.equal(isValidContainerNumber('CSQ3054383'), false);
  assert.equal(isValidContainerNumber('CSQX3054383'), false);
});

test('normalises spacing and case', () => {
  assert.equal(normaliseContainerNumber(' csqu 305438-3 '), 'CSQU3054383');
});

test('check digit of the ISO 6346 example', () => {
  assert.equal(checkDigit('CSQU305438'), 3);
});
