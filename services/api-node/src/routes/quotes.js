import { Router } from 'express';
import { ridgewayQuotes } from '../carriers/ratingClient.js';
import { cacheShard, canonicalQuery, cacheTtl, responseCacheKey } from '../cache/hashKeys.js';
import { asyncHandler, badRequest } from '../middleware/errors.js';
import { childLogger } from '../logger.js';

const log = childLogger('quotes');

/** @type {Map<string, { expiresAt: number, value: unknown }>[]} */
const shards = [];

/**
 * @param {string} key
 */
function shardFor(key) {
  const index = cacheShard(key);
  shards[index] ??= new Map();
  return shards[index];
}

/**
 * @param {any} query
 */
function quoteRequest(query) {
  const weightGrams = Number(query.weightGrams);
  const dims = ['lengthCm', 'widthCm', 'heightCm'].map((k) => Number(query[k]));
  if (!(weightGrams > 0) || dims.some((d) => !(d > 0))) return null;
  if (typeof query.from !== 'string' || typeof query.to !== 'string') return null;
  return {
    originPostcode: query.from,
    destinationPostcode: query.to,
    destinationCountry: typeof query.country === 'string' ? query.country : 'GB',
    weightGrams,
    dimensions: { lengthCm: dims[0], widthCm: dims[1], heightCm: dims[2] },
    service: query.service === 'express' || query.service === 'economy' ? query.service : 'standard',
  };
}

export function quoteRoutes() {
  const router = Router();
  router.get(
    '/',
    asyncHandler(async (req, res) => {
      const request = quoteRequest(req.query);
      if (!request) throw badRequest('quote_request_invalid');
      const url = new URL(req.originalUrl, 'https://gateway.invalid');
      const key = responseCacheKey(String(req.get('x-tenant-id') ?? 'public'), '/v1/quotes', canonicalQuery(url.searchParams));
      const shard = shardFor(key);
      const hit = shard.get(key);
      if (hit && hit.expiresAt > Date.now()) {
        res.json(hit.value);
        return;
      }
      try {
        const quotes = await ridgewayQuotes(request);
        shard.set(key, { expiresAt: Date.now() + cacheTtl('/v1/quotes') * 1000, value: { quotes } });
        res.json({ quotes });
      } catch (err) {
        log.warn({ err: String(err) }, 'carrier quote failed');
        res.status(502).json({ error: 'carrier_unavailable' });
      }
    }),
  );
  return router;
}
