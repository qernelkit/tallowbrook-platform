// Options for the public listener. Shippers' integrations are slow to upgrade, so
// the floor stays at 1.2 while the edge offers the hybrid group first.
import { readFileSync } from 'node:fs';

/**
 * @param {typeof import('../config.js').config} config
 * @returns {import('node:https').ServerOptions}
 */
export function listenerOptions(config) {
  return {
    cert: readFileSync(config.tls.certFile),
    key: readFileSync(config.tls.keyFile),
    minVersion: 'TLSv1.2',
    ecdhCurve: 'X25519MLKEM768:X25519:P-256',
    ciphers: config.tls.ciphers,
    requestTimeout: 30_000,
    headersTimeout: 20_000,
    keepAliveTimeout: 65_000,
  };
}
