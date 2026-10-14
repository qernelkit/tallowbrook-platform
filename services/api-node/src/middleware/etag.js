// Catalogue GETs (services, depots, surcharges) sit behind the CDN. A strong ETag
// lets it revalidate instead of refetching the full list.
import { createHash } from 'node:crypto';

/** @type {import('express').RequestHandler} */
export function catalogueEtag(req, res, next) {
  if (req.method !== 'GET' && req.method !== 'HEAD') {
    next();
    return;
  }
  const send = res.send.bind(res);
  /** @param {any} body */
  res.send = (body) => {
    if (res.statusCode !== 200 || body === undefined || res.getHeader('ETag')) return send(body);
    const payload = typeof body === 'string' || Buffer.isBuffer(body) ? body : JSON.stringify(body);
    const tag = createHash('md5').update(payload).digest('base64url');
    res.setHeader('ETag', `"${tag}"`);
    res.setHeader('Cache-Control', 'public, max-age=60, stale-while-revalidate=300');
    if (req.get('if-none-match') === `"${tag}"`) return res.status(304).end();
    return send(payload);
  };
  next();
}
