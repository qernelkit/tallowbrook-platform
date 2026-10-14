import assert from 'node:assert/strict';
import { test } from 'node:test';
import { totalWeightGrams, validateBooking } from '../../src/validation/shipment.js';

const address = (overrides = {}) => ({
  name: 'Mara Ellison',
  street: '14 Quay Street',
  city: 'Bristol',
  postcode: 'BS1 4DJ',
  country: 'GB',
  ...overrides,
});

const booking = (overrides = {}) => ({
  service: 'standard',
  sender: address(),
  consignee: address({ name: 'Dockside Supplies', postcode: 'SO14 3TL', city: 'Southampton' }),
  parcels: [{ weightGrams: 2500, lengthCm: 40, widthCm: 30, heightCm: 20 }],
  ...overrides,
});

test('a complete booking has no errors', () => {
  assert.deepEqual(validateBooking(booking()), {});
});

test('unknown service is reported', () => {
  assert.match(validateBooking(booking({ service: 'teleport' })).service, /one of/);
});

test('postcode format is checked per country', () => {
  const errors = validateBooking(booking({ consignee: address({ postcode: '12345' }) }));
  assert.equal(errors['consignee.postcode'], 'postcode format');
});

test('ocean services need known ports', () => {
  const errors = validateBooking(booking({ service: 'ocean-fcl', portOfLoading: 'GBFXT', portOfDischarge: 'XXXXX' }));
  assert.equal(errors.portOfDischarge, 'known UN/LOCODE');
  assert.equal(errors.portOfLoading, undefined);
});

test('parcel limits', () => {
  const errors = validateBooking(booking({ parcels: [{ weightGrams: 80_000, lengthCm: 40, widthCm: 30, heightCm: 400 }] }));
  assert.ok(errors['parcels[0].weightGrams']);
  assert.ok(errors['parcels[0].heightCm']);
});

test('total weight', () => {
  assert.equal(totalWeightGrams(booking({ parcels: [{ weightGrams: 1000 }, { weightGrams: 1500 }] })), 2500);
});
