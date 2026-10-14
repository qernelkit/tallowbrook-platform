// Signs and delivers webhook events to shipper endpoints.
import { createHmac, randomUUID } from 'node:crypto';
import { config } from '../config.js';
import { childLogger } from '../logger.js';
import { contentDigest } from '../middleware/contentDigest.js';
import { DELIVERY_HEADER, EVENT_HEADER, RETRY_DELAYS_SECONDS, SIGNATURE_HEADER, WEBHOOK_HMAC_DIGEST } from './constants.js';

const log = childLogger('webhooks');

/**
 * @typedef {object} Endpoint
 * @property {string} id
 * @property {string} url
 * @property {string} secret
 * @property {string[]} events
 */

/**
 * @param {{ secret: string }} endpoint
 * @param {Buffer} body
 * @returns {Record<string, string>}
 */
export function signDelivery(endpoint, body) {
  const mac = createHmac(WEBHOOK_HMAC_DIGEST, endpoint.secret).update(body).digest('hex');
  return { [SIGNATURE_HEADER]: mac };
}

/**
 * @param {number} attempt zero-based
 * @returns {number | null} seconds until the next attempt, or null to give up
 */
export function nextRetryDelay(attempt) {
  if (attempt + 1 >= config.webhooks.maxAttempts) return null;
  return RETRY_DELAYS_SECONDS[Math.min(attempt, RETRY_DELAYS_SECONDS.length - 1)];
}

/**
 * @param {Endpoint} endpoint
 * @param {string} eventType
 * @param {object} data
 * @returns {Promise<{ delivered: boolean, status: number | null }>}
 */
export async function deliverEvent(endpoint, eventType, data) {
  if (!endpoint.events.includes(eventType) && !endpoint.events.includes('*')) {
    return { delivered: false, status: null };
  }
  const deliveryId = randomUUID();
  const body = Buffer.from(JSON.stringify({ id: deliveryId, type: eventType, createdAt: new Date().toISOString(), data }));
  const headers = {
    'content-type': 'application/json',
    [EVENT_HEADER]: eventType,
    [DELIVERY_HEADER]: deliveryId,
    'content-digest': await contentDigest(body),
    ...signDelivery(endpoint, body),
  };
  try {
    const res = await fetch(endpoint.url, {
      method: 'POST',
      headers,
      body,
      signal: AbortSignal.timeout(config.webhooks.deliveryTimeoutMs),
    });
    log.info({ endpoint: endpoint.id, eventType, status: res.status }, 'webhook delivered');
    return { delivered: res.ok, status: res.status };
  } catch (err) {
    log.warn({ endpoint: endpoint.id, eventType, err: String(err) }, 'webhook delivery failed');
    return { delivered: false, status: null };
  }
}
