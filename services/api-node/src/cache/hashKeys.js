// Response-cache keys and shard choice for the catalogue and quote caches.
import CRC32 from 'crc-32';
import { config } from '../config.js';

const CACHE_SHARDS = config.cache.shards;

const ROUTE_TTL_SECONDS = {
  '/v1/catalogue/services': 300,
  '/v1/catalogue/depots': 900,
  '/v1/quotes': 30,
};

/**
 * @param {string} tenantId
 * @param {string} route
 * @param {string} query canonical query string
 */
export function responseCacheKey(tenantId, route, query) {
  const cacheKey = Buffer.from(`${tenantId}:${route}:${query}`).toString('base64');
  return cacheKey;
}

/**
 * @param {string} cacheKey
 */
export function cacheShard(cacheKey) {
  return (CRC32.str(cacheKey) >>> 0) % CACHE_SHARDS;
}

/**
 * @param {string} route
 */
export function cacheTtl(route) {
  return ROUTE_TTL_SECONDS[route] ?? config.cache.defaultMaxAgeSeconds;
}

/**
 * @param {URLSearchParams} params
 */
export function canonicalQuery(params) {
  return [...params.entries()]
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
    .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`)
    .join('&');
}
