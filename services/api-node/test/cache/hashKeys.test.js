import assert from 'node:assert/strict';
import { test } from 'node:test';
import { cacheShard, cacheTtl, canonicalQuery, responseCacheKey } from '../../src/cache/hashKeys.js';

test('query order does not change the key', () => {
  const a = canonicalQuery(new URLSearchParams('to=BS1&from=SO14&weightGrams=500'));
  const b = canonicalQuery(new URLSearchParams('weightGrams=500&from=SO14&to=BS1'));
  assert.equal(responseCacheKey('t1', '/v1/quotes', a), responseCacheKey('t1', '/v1/quotes', b));
});

test('shard is stable and in range', () => {
  const key = responseCacheKey('t1', '/v1/quotes', 'from=SO14');
  const shard = cacheShard(key);
  assert.equal(cacheShard(key), shard);
  assert.ok(shard >= 0 && shard < 16);
});

test('per-route ttl with a default', () => {
  assert.equal(cacheTtl('/v1/quotes'), 30);
  assert.equal(cacheTtl('/v1/unknown'), 60);
});
