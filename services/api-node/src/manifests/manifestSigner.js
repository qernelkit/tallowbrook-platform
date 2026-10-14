// Customs manifest signatures for the Harbor customs pilot. The pilot key is a raw
// secret key file provisioned by the customs integration team.
import { readFileSync } from 'node:fs';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';
import { config } from '../config.js';
import { canonicalJson } from '../receipts/receiptSigner.js';

/** @type {Uint8Array | undefined} */
let pilotKey;

function manifestKey() {
  pilotKey ??= new Uint8Array(readFileSync(config.manifests.keyFile));
  return pilotKey;
}

/**
 * @typedef {object} CustomsManifest
 * @property {string} manifestId
 * @property {string} vessel
 * @property {string} portOfLoading UN/LOCODE
 * @property {string} portOfDischarge UN/LOCODE
 * @property {{ containerNumber: string, sealNumber: string, grossKg: number }[]} containers
 */

/**
 * @param {CustomsManifest} manifest
 */
export function signCustomsManifest(manifest) {
  if (manifest.containers.length === 0) throw new Error('manifest has no containers');
  const manifestBytes = new TextEncoder().encode(canonicalJson(manifest));
  const signature = ml_dsa65.sign(manifestBytes, manifestKey());
  return { manifestId: manifest.manifestId, signature: Buffer.from(signature).toString('base64') };
}
