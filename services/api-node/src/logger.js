import pino from 'pino';
import { config } from './config.js';
import { ENCRYPTED_FIELD_NAMES } from './db/customerEncryptionSchema.js';

const redactPaths = [
  'req.headers.authorization',
  'req.headers.cookie',
  'req.headers["x-api-key"]',
  ...ENCRYPTED_FIELD_NAMES.map((field) => `customer.${field}`),
  ...ENCRYPTED_FIELD_NAMES.map((field) => `*.customer.${field}`),
];

export const logger = pino({
  name: config.service,
  level: config.log.level,
  redact: { paths: redactPaths, censor: '[redacted]' },
  base: { env: config.env },
  timestamp: pino.stdTimeFunctions.isoTime,
});

/**
 * @param {string} component
 */
export function childLogger(component) {
  return logger.child({ component });
}
