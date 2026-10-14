// Request validation for shipment bookings. Errors are collected per field so the web
// app can show them next to the inputs.
import { isKnownPort } from '../shipping/ports.js';
import { isValidContainerNumber } from '../shipping/containerNumbers.js';

export const SERVICES = ['standard', 'express', 'economy', 'ocean-fcl', 'ocean-lcl'];
const POSTCODE = {
  GB: /^[A-Z]{1,2}\d[A-Z\d]? ?\d[A-Z]{2}$/i,
  NL: /^\d{4} ?[A-Z]{2}$/i,
  DE: /^\d{5}$/,
  US: /^\d{5}(-\d{4})?$/,
};

/**
 * @param {Record<string, string>} errors
 * @param {string} field
 * @param {string} message
 */
function fail(errors, field, message) {
  if (!errors[field]) errors[field] = message;
}

/**
 * @param {any} address
 * @param {string} prefix
 * @param {Record<string, string>} errors
 */
function checkAddress(address, prefix, errors) {
  if (!address || typeof address !== 'object') {
    fail(errors, prefix, 'required');
    return;
  }
  if (typeof address.name !== 'string' || address.name.trim().length < 2) fail(errors, `${prefix}.name`, 'required');
  if (typeof address.street !== 'string' || !address.street.trim()) fail(errors, `${prefix}.street`, 'required');
  if (typeof address.city !== 'string' || !address.city.trim()) fail(errors, `${prefix}.city`, 'required');
  if (typeof address.country !== 'string' || !/^[A-Z]{2}$/.test(address.country)) {
    fail(errors, `${prefix}.country`, 'two-letter country code');
    return;
  }
  const pattern = POSTCODE[address.country];
  if (pattern && !pattern.test(String(address.postcode ?? ''))) fail(errors, `${prefix}.postcode`, 'postcode format');
  if (address.phone !== undefined && !/^\+?[\d\s()-]{7,20}$/.test(String(address.phone))) fail(errors, `${prefix}.phone`, 'phone format');
}

/**
 * @param {any} body
 * @returns {Record<string, string>} field errors; empty when valid
 */
export function validateBooking(body) {
  /** @type {Record<string, string>} */
  const errors = {};
  if (!body || typeof body !== 'object') return { body: 'expected a JSON object' };
  if (!SERVICES.includes(body.service)) fail(errors, 'service', `one of ${SERVICES.join(', ')}`);
  checkAddress(body.sender, 'sender', errors);
  checkAddress(body.consignee, 'consignee', errors);
  if (!Array.isArray(body.parcels) || body.parcels.length === 0) {
    fail(errors, 'parcels', 'at least one parcel');
  } else {
    body.parcels.forEach((parcel, i) => {
      if (!(parcel.weightGrams > 0 && parcel.weightGrams <= 70_000)) fail(errors, `parcels[${i}].weightGrams`, '1 g to 70 kg');
      for (const side of ['lengthCm', 'widthCm', 'heightCm']) {
        if (!(parcel[side] > 0 && parcel[side] <= 300)) fail(errors, `parcels[${i}].${side}`, '1 to 300 cm');
      }
    });
  }
  if (String(body.service).startsWith('ocean-')) {
    if (!isKnownPort(String(body.portOfLoading ?? ''))) fail(errors, 'portOfLoading', 'known UN/LOCODE');
    if (!isKnownPort(String(body.portOfDischarge ?? ''))) fail(errors, 'portOfDischarge', 'known UN/LOCODE');
    if (body.containerNumber !== undefined && !isValidContainerNumber(String(body.containerNumber))) {
      fail(errors, 'containerNumber', 'ISO 6346 container number');
    }
  }
  if (body.collectionDate !== undefined) {
    const date = new Date(body.collectionDate);
    if (Number.isNaN(date.getTime())) fail(errors, 'collectionDate', 'ISO date');
    else if (date.getTime() < Date.now() - 86_400_000) fail(errors, 'collectionDate', 'not in the past');
  }
  if (body.deliveryNote !== undefined && String(body.deliveryNote).length > 500) fail(errors, 'deliveryNote', 'at most 500 characters');
  return errors;
}

/**
 * @param {any} body
 */
export function totalWeightGrams(body) {
  return (body.parcels ?? []).reduce((sum, parcel) => sum + Number(parcel.weightGrams || 0), 0);
}
