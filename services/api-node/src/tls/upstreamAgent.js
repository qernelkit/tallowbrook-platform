// Agent for calls from the gateway to payments and ledger.
import https from 'node:https';
import { readFileSync } from 'node:fs';
import { config } from '../config.js';
import { TALLOWBROOK_ROOT_E2, splitBundle } from './trustAnchors.js';

const extraAnchors = config.upstream.extraCaFile ? splitBundle(readFileSync(config.upstream.extraCaFile, 'utf8')) : [];

export const upstreamAgent = new https.Agent({
  minVersion: config.upstream.minTlsVersion,
  sigalgs: config.upstream.sigalgs,
  ca: [TALLOWBROOK_ROOT_E2, ...extraAnchors],
  keepAlive: true,
  maxSockets: config.upstream.maxSockets,
});

/**
 * POSTs JSON to an internal service and resolves with the parsed reply.
 * @param {string} url
 * @param {unknown} payload
 * @returns {Promise<any>}
 */
export function postInternal(url, payload) {
  const body = Buffer.from(JSON.stringify(payload));
  return new Promise((resolve, reject) => {
    const req = https.request(
      url,
      {
        method: 'POST',
        agent: upstreamAgent,
        timeout: config.upstream.timeoutMs,
        headers: { 'content-type': 'application/json', 'content-length': body.length },
      },
      (res) => {
        const chunks = [];
        res.on('data', (chunk) => chunks.push(chunk));
        res.on('end', () => {
          const text = Buffer.concat(chunks).toString('utf8');
          if ((res.statusCode ?? 500) >= 400) {
            reject(new Error(`${url} answered ${res.statusCode}: ${text.slice(0, 200)}`));
            return;
          }
          resolve(text ? JSON.parse(text) : null);
        });
      },
    );
    req.on('timeout', () => req.destroy(new Error(`${url} timed out`)));
    req.on('error', reject);
    req.end(body);
  });
}
