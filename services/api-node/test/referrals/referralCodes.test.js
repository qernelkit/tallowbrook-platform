import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { before, test } from 'node:test';
import { decodeReferral, encodeReferral } from '../../src/referrals/referralCodes.js';

before(() => {
  process.env.REFERRAL_MASK = randomBytes(6).toString('hex');
});

test('codes round-trip', () => {
  for (const id of [0, 1, 42, 99_999, 2 ** 40 + 7]) {
    assert.equal(decodeReferral(encodeReferral(id)), id);
  }
});

test('neighbouring ids do not give neighbouring codes', () => {
  const a = encodeReferral(1000);
  const b = encodeReferral(1001);
  assert.notEqual(a.slice(0, 8), b.slice(0, 8));
});

test('decoding accepts lower case and look-alike letters', () => {
  const code = encodeReferral(31337);
  assert.equal(decodeReferral(code.toLowerCase()), 31337);
});

test('rejects garbage', () => {
  assert.throws(() => decodeReferral('not-a-code!'));
});
