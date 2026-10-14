// Monthly archive of customs entries for the broker's records team. They open it with
// a shared password agreed per quarter, so it is password-encrypted OpenPGP.
import { createMessage, encrypt } from 'openpgp';
import { secret } from '../config.js';

const COLUMNS = ['entryNumber', 'shipmentId', 'declaredAt', 'procedure', 'hsCode', 'valueMinor', 'currency', 'status'];

/**
 * @param {Record<string, unknown>[]} entries
 */
function toCsv(entries) {
  const quote = (value) => {
    const text = value === null || value === undefined ? '' : String(value);
    return /[",\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
  };
  return [COLUMNS.join(','), ...entries.map((entry) => COLUMNS.map((c) => quote(entry[c])).join(','))].join('\n');
}

/**
 * @param {string} month yyyy-mm
 * @param {Record<string, unknown>[]} entries
 * @returns {Promise<{ fileName: string, armored: string }>}
 */
export async function exportMonthlyArchive(month, entries) {
  if (!/^\d{4}-\d{2}$/.test(month)) throw new Error(`bad archive month ${month}`);
  const archivePassword = secret('CUSTOMS_ARCHIVE_PASSWORD');
  const message = await createMessage({ text: toCsv(entries) });
  const armored = await encrypt({ message, passwords: [archivePassword] });
  return { fileName: `customs-archive-${month}.csv.asc`, armored };
}
