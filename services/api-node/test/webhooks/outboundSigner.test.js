import assert from 'node:assert/strict';
import { createHmac, randomBytes } from 'node:crypto';
import { describe, test } from 'node:test';
import { SIGNATURE_HEADER } from '../../src/webhooks/constants.js';
import { nextRetryDelay, signDelivery } from '../../src/webhooks/outboundSigner.js';

const FIXTURE_SECRET = `whsec_${randomBytes(64).toString('base64url')}`;
const body = Buffer.from(JSON.stringify({ id: 'evt_1', type: 'shipment.delivered', data: { shipmentId: 'shp_000000042' } }));

describe('signDelivery', () => {
  test('header is the hex MAC of the raw body under the endpoint secret', () => {
    const headers = signDelivery({ secret: FIXTURE_SECRET }, body);
    const expected = createHmac('sha512', FIXTURE_SECRET).update(body).digest('hex');
    assert.equal(headers[SIGNATURE_HEADER], expected);
  });

  test('a different body gives a different header', () => {
    const other = Buffer.from(body.toString('utf8').replace('evt_1', 'evt_2'));
    assert.notEqual(
      signDelivery({ secret: FIXTURE_SECRET }, other)[SIGNATURE_HEADER],
      signDelivery({ secret: FIXTURE_SECRET }, body)[SIGNATURE_HEADER],
    );
  });

  test('only the signature header is produced', () => {
    assert.deepEqual(Object.keys(signDelivery({ secret: FIXTURE_SECRET }, body)), [SIGNATURE_HEADER]);
  });
});

describe('nextRetryDelay', () => {
  test('backs off and then gives up', () => {
    assert.equal(nextRetryDelay(0), 10);
    assert.equal(nextRetryDelay(3), 1800);
    assert.equal(nextRetryDelay(7), null);
  });
});
