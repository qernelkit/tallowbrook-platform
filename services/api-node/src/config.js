// Runtime configuration: config/default.json, read once at boot, plus a few values
// that differ per environment. Secrets never live in the file; `secret()` reads them
// from the environment the deploy tooling populates.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const CONFIG_PATH = fileURLToPath(new URL('../config/default.json', import.meta.url));

/**
 * @template T
 * @param {T} value
 * @returns {T}
 */
function deepFreeze(value) {
  if (value && typeof value === 'object') {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

function load() {
  const base = JSON.parse(readFileSync(CONFIG_PATH, 'utf8'));
  base.env = process.env.NODE_ENV ?? 'development';
  base.listen.port = Number(process.env.PORT ?? base.listen.port);
  base.log.level = process.env.LOG_LEVEL ?? base.log.level;
  base.mongo.uri = process.env.MONGO_URI ?? base.mongo.uri;
  base.publicIds.salt = process.env.PUBLIC_ID_SALT ?? '';
  return deepFreeze(base);
}

export const config = load();

/**
 * Reads a secret injected by the deploy tooling. Throws on first use when it is
 * missing so a misconfigured pod fails its readiness probe instead of serving.
 * @param {string} name
 * @returns {string}
 */
export function secret(name) {
  const value = process.env[name];
  if (value === undefined || value === '') {
    throw new Error(`secret ${name} is not set`);
  }
  return value;
}

/**
 * @param {string} name
 * @returns {Buffer}
 */
export function secretBytes(name) {
  return Buffer.from(secret(name), 'base64');
}
