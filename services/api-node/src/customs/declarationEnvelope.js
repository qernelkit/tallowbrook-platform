// Export declarations go to the customs broker as compact JWE, encrypted to the
// broker's published key.
import { readFileSync } from 'node:fs';
import { CompactEncrypt, importSPKI } from 'jose';
import { config } from '../config.js';

/** @type {ReturnType<typeof importSPKI> | undefined} */
let brokerKey;

function brokerDeclarationKey() {
  if (!brokerKey) {
    const brokerKeyPem = readFileSync(config.customs.brokerKeyFile, 'utf8');
    brokerKey = importSPKI(brokerKeyPem, 'RSA-OAEP-256');
  }
  return brokerKey;
}

/**
 * @typedef {object} ExportDeclaration
 * @property {string} shipmentId
 * @property {string} exporterEori
 * @property {string} consigneeCountry
 * @property {{ hsCode: string, description: string, valueMinor: number, currency: string, netKg: number }[]} items
 */

/**
 * @param {ExportDeclaration} declaration
 * @returns {string[]}
 */
export function declarationProblems(declaration) {
  const problems = [];
  if (!/^[A-Z]{2}[A-Z0-9]{1,15}$/.test(declaration.exporterEori)) problems.push('exporterEori');
  if (!/^[A-Z]{2}$/.test(declaration.consigneeCountry)) problems.push('consigneeCountry');
  if (declaration.items.length === 0) problems.push('items');
  declaration.items.forEach((item, i) => {
    if (!/^\d{6,10}$/.test(item.hsCode)) problems.push(`items[${i}].hsCode`);
    if (item.valueMinor <= 0) problems.push(`items[${i}].valueMinor`);
  });
  return problems;
}

/**
 * @param {ExportDeclaration} declaration
 * @returns {Promise<string>}
 */
export async function envelopeDeclaration(declaration) {
  const plaintext = new TextEncoder().encode(JSON.stringify(declaration));
  return new CompactEncrypt(plaintext)
    .setProtectedHeader({
      alg: 'RSA-OAEP-256',
      enc: 'A256GCM',
      kid: config.customs.brokerKeyId,
      cty: 'application/vnd.tallowbrook.export-declaration+json',
    })
    .encrypt(await brokerDeclarationKey());
}
