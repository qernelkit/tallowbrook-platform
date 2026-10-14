// Nightly consignment manifest for carriers that collect from our depots.
import { createCipheriv } from 'node:crypto';
import { secret } from '../config.js';
import { carrierProfile } from './carrierProfiles.js';

/**
 * @typedef {object} ManifestLine
 * @property {string} consignment
 * @property {number} pieces
 * @property {number} weightKg
 * @property {string} postcode
 * @property {string} country
 * @property {string} service
 */

/**
 * @param {unknown} value
 */
function csvField(value) {
  const text = value === undefined || value === null ? '' : String(value);
  return /[",\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
}

/**
 * @param {ManifestLine[]} lines
 * @param {string[]} columns
 */
export function toCsv(lines, columns) {
  const rows = [columns.join(',')];
  for (const line of lines) rows.push(columns.map((column) => csvField(line[column])).join(','));
  return rows.join('\n') + '\n';
}

/**
 * @param {string} carrierId
 * @param {Date} day
 */
export function manifestFileName(carrierId, day) {
  const stamp = day.toISOString().slice(0, 10).replace(/-/g, '');
  return `TB_${carrierId.toUpperCase().replace(/-/g, '_')}_${stamp}.csv`;
}

/**
 * Builds the file uploaded to the carrier's SFTP drop.
 * @param {string} carrierId
 * @param {ManifestLine[]} lines
 * @returns {Buffer}
 */
export function buildManifestFile(carrierId, lines) {
  const profile = carrierProfile(carrierId);
  const csv = toCsv(lines, profile.columns);
  if (!profile.exportCipher) return Buffer.from(csv, 'utf8');
  const exportKey = Buffer.from(secret(`MANIFEST_KEY_${carrierId.toUpperCase().replace(/-/g, '_')}`), 'hex');
  const iv = Buffer.from(profile.exportIvHex, 'hex');
  const stream = createCipheriv(profile.exportCipher, exportKey, iv);
  return Buffer.concat([stream.update(csv, 'utf8'), stream.final()]);
}
