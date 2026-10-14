// Rate quotes from Ridgeway Parcel. Ridgeway rotates its edge certificate every
// month but keeps the key, so the client checks the key instead of the chain alone.
import https from 'node:https';
import tls from 'node:tls';
import { createHash } from 'node:crypto';
import { config } from '../config.js';
import { childLogger } from '../logger.js';

const log = childLogger('rating');

// Primary and standby keys, as published in Ridgeway's integration guide (rev. 14).
const CARRIER_SPKI_PINS = new Set(['jKZhvnw2ZzjP5SEHLlWMSccDlBeKGN/+TIbfo1fE+w0=', 'tIUX92LySE+TEo98kQSxiCqmRv8mrCYRVnD6bJcYoZg=']);

/**
 * @param {string} host
 * @param {import('node:tls').PeerCertificate} cert
 * @returns {Error | undefined}
 */
function checkRidgewayIdentity(host, cert) {
  const failure = tls.checkServerIdentity(host, cert);
  if (failure) return failure;
  const presented = createHash('sha256').update(cert.pubkey).digest('base64');
  if (!CARRIER_SPKI_PINS.has(presented)) {
    log.warn({ host, presented }, 'carrier key not in the pinned set');
    return new Error(`unexpected key presented by ${host}`);
  }
  return undefined;
}

/**
 * @typedef {object} QuoteRequest
 * @property {string} originPostcode
 * @property {string} destinationPostcode
 * @property {string} destinationCountry
 * @property {number} weightGrams
 * @property {{ lengthCm: number, widthCm: number, heightCm: number }} dimensions
 * @property {'standard' | 'express' | 'economy'} service
 */

/**
 * @typedef {object} Quote
 * @property {string} carrier
 * @property {string} service
 * @property {number} amountMinor
 * @property {string} currency
 * @property {string} estimatedDelivery
 */

/**
 * @param {QuoteRequest} request
 * @returns {Promise<Quote[]>}
 */
export function ridgewayQuotes(request) {
  const body = JSON.stringify({
    from: { postcode: request.originPostcode, country: 'GB' },
    to: { postcode: request.destinationPostcode, country: request.destinationCountry },
    parcel: {
      weight_g: request.weightGrams,
      length_cm: request.dimensions.lengthCm,
      width_cm: request.dimensions.widthCm,
      height_cm: request.dimensions.heightCm,
    },
    service_level: request.service,
  });
  const { ratingHost, ratingPath, timeoutMs } = config.carriers.ridgeway;

  return new Promise((resolve, reject) => {
    const req = https.request(
      {
        host: ratingHost,
        path: ratingPath,
        method: 'POST',
        timeout: timeoutMs,
        checkServerIdentity: checkRidgewayIdentity,
        headers: { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body) },
      },
      (res) => {
        let text = '';
        res.setEncoding('utf8');
        res.on('data', (chunk) => (text += chunk));
        res.on('end', () => {
          if (res.statusCode !== 200) {
            reject(new Error(`ridgeway quote failed with ${res.statusCode}`));
            return;
          }
          resolve(toQuotes(JSON.parse(text)));
        });
      },
    );
    req.on('timeout', () => req.destroy(new Error('ridgeway quote timed out')));
    req.on('error', reject);
    req.end(body);
  });
}

/**
 * @param {any} reply
 * @returns {Quote[]}
 */
function toQuotes(reply) {
  const offers = Array.isArray(reply?.offers) ? reply.offers : [];
  return offers
    .filter((offer) => offer.available !== false)
    .map((offer) => ({
      carrier: 'ridgeway-parcel',
      service: String(offer.service_level),
      amountMinor: Math.round(Number(offer.price) * 100),
      currency: String(offer.currency ?? 'GBP'),
      estimatedDelivery: String(offer.eta_date),
    }))
    .sort((a, b) => a.amountMinor - b.amountMinor);
}
