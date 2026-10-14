'use strict';
// Tracking callbacks from carriers on the 2017 integration. Each callback carries
// X-Tracking-Tag, computed by the carrier over its shared secret followed by the body.
const { createHash, timingSafeEqual } = require('node:crypto');

const KNOWN_EVENTS = new Set(['collected', 'in_transit', 'out_for_delivery', 'delivered', 'exception', 'returned']);

/**
 * @param {{ sharedSecret: string }} carrier
 * @param {string} rawBody
 * @param {string | undefined} tagHeader
 */
function tagMatches(carrier, rawBody, tagHeader) {
  const expected = createHash('sha1')
    .update(carrier.sharedSecret + rawBody)
    .digest('hex');
  const given = Buffer.from(String(tagHeader ?? ''), 'hex');
  const wanted = Buffer.from(expected, 'hex');
  return given.length === wanted.length && timingSafeEqual(given, wanted);
}

/**
 * @param {any} body
 * @returns {{ trackingNumber: string, event: string, at: Date, location: string | null } | null}
 */
function parseCallback(body) {
  if (!body || typeof body.tracking_number !== 'string') return null;
  if (!KNOWN_EVENTS.has(body.event)) return null;
  const at = new Date(body.timestamp);
  if (Number.isNaN(at.getTime())) return null;
  return {
    trackingNumber: body.tracking_number.trim().toUpperCase(),
    event: body.event,
    at,
    location: typeof body.location === 'string' ? body.location : null,
  };
}

/**
 * @param {(carrierId: string) => Promise<{ sharedSecret: string } | null>} findCarrier
 * @param {(event: NonNullable<ReturnType<typeof parseCallback>>, carrierId: string) => Promise<void>} record
 * @returns {import('express').RequestHandler}
 */
function trackingCallbackHandler(findCarrier, record) {
  return async (req, res, next) => {
    try {
      const carrierId = String(req.params.carrierId);
      const carrier = await findCarrier(carrierId);
      if (!carrier) return res.status(404).end();
      const rawBody = Buffer.isBuffer(req.body) ? req.body.toString('utf8') : '';
      if (!tagMatches(carrier, rawBody, req.get('x-tracking-tag'))) return res.status(401).end();
      const event = parseCallback(JSON.parse(rawBody));
      if (!event) return res.status(422).json({ error: 'unrecognised_event' });
      await record(event, carrierId);
      return res.status(204).end();
    } catch (err) {
      return next(err);
    }
  };
}

module.exports = { trackingCallbackHandler, parseCallback };
