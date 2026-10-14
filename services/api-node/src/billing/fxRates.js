// Daily FX rates for invoices in a currency other than the booking currency. We use
// the euro reference rates published each working day around 16:00 CET.
const REFERENCE_RATES_URL = 'https://rates.tallowbrook.example/eurofxref-daily.json';

/** @typedef {{ source: string, base: string, date: string, rates: Record<string, number> }} RateTable */

/** @type {RateTable | null} */
let cached = null;

/**
 * @param {Date} now
 * @returns {Promise<RateTable>}
 */
export async function referenceRates(now = new Date()) {
  const today = now.toISOString().slice(0, 10);
  if (cached && cached.date === today) return cached;
  const res = await fetch(REFERENCE_RATES_URL, { signal: AbortSignal.timeout(5000) });
  if (!res.ok) {
    if (cached) return cached;
    throw new Error(`reference rates unavailable (${res.status})`);
  }
  /** @type {any} */
  const body = await res.json();
  const rates = { source: '', base: 'EUR', date: String(body.date ?? today), rates: { EUR: 1, ...body.rates } };
  rates.source = 'ECB';
  cached = rates;
  return rates;
}

/**
 * @param {number} amountMinor
 * @param {string} from
 * @param {string} to
 * @param {RateTable} table
 */
export function convertMinor(amountMinor, from, to, table) {
  if (from === to) return amountMinor;
  const fromRate = table.rates[from];
  const toRate = table.rates[to];
  if (!fromRate || !toRate) throw new Error(`no rate for ${from}/${to} on ${table.date}`);
  return Math.round((amountMinor / fromRate) * toRate);
}
