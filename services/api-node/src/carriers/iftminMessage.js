// IFTMIN (instruction message) builder for Kestrel Haulage bookings, D:04A.
import { secret } from '../config.js';
import edifact from './edifactFields.cjs';

const SENDER_ID = 'TALLOWBROOK';
const RECIPIENT_ID = 'KESTRELHAUL';

/**
 * @typedef {object} Booking
 * @property {string} reference
 * @property {Date} collectionDate
 * @property {{ name: string, phone: string, street: string, city: string, postcode: string, country: string }} consignee
 * @property {{ pieces: number, weightKg: number, description: string }} goods
 */

/**
 * @param {Date} date
 */
function ediDate(date) {
  return date.toISOString().slice(0, 10).replace(/-/g, '');
}

/**
 * @param {Date} date
 */
function ediTime(date) {
  return date.toISOString().slice(11, 16).replace(':', '');
}

/**
 * @param {Booking} booking
 * @param {number} controlRef
 * @param {Date} now
 * @returns {string}
 */
export function buildIftmin(booking, controlRef, now = new Date()) {
  const fieldKey = Buffer.from(secret('KESTREL_FIELD_KEY'), 'hex');
  const esc = edifact.escapeEdifact;
  const ref = String(controlRef).padStart(9, '0');
  const segments = [
    `UNB+UNOC:3+${SENDER_ID}+${RECIPIENT_ID}+${ediDate(now).slice(2)}:${ediTime(now)}+${ref}'`,
    `UNH+1+IFTMIN:D:04A:UN'`,
    `BGM+610+${esc(booking.reference)}+9'`,
    `DTM+234:${ediDate(booking.collectionDate)}:102'`,
    `NAD+CN+++${esc(booking.consignee.street)}+${esc(booking.consignee.city)}++${esc(booking.consignee.postcode)}+${booking.consignee.country}'`,
    `FTX+AAI+++${edifact.encryptConsigneeField(booking.consignee.name, fieldKey)}'`,
    `FTX+AAJ+++${edifact.encryptConsigneeField(booking.consignee.phone, fieldKey)}'`,
    `GID+1+${booking.goods.pieces}:PK'`,
    `FTX+AAA+++${esc(booking.goods.description.slice(0, 70))}'`,
    `MEA+AAE+G+KGM:${booking.goods.weightKg.toFixed(1)}'`,
  ];
  const message = [...segments, `UNT+${segments.length}+1'`];
  return [...message, `UNZ+1+${ref}'`].join('\n');
}
