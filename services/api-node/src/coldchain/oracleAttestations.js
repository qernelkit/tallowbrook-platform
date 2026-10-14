// Cold-chain readings for pharma shipments come from an oracle committee of reefer
// telemetry providers. Each reading carries one aggregated signature from the members
// that saw it; the gateway accepts it only if the quorum's combined key verifies.
import { bls12_381 } from '@noble/curves/bls12-381.js';
import { hexToBytes } from '@noble/curves/utils.js';
import { canonicalJson } from '../receipts/receiptSigner.js';

const ORACLE_DST = 'TB-COLDCHAIN-READING-V1';
const QUORUM = 3;

/**
 * @typedef {object} ColdChainReading
 * @property {string} containerNumber
 * @property {number} celsius
 * @property {string} at ISO time
 * @property {string[]} signers member ids
 * @property {string} signature hex
 */

/**
 * @param {ColdChainReading} reading
 * @param {Map<string, string>} committee member id to public key hex
 */
export function readingIsAttested(reading, committee) {
  const memberKeys = [...new Set(reading.signers)].map((id) => committee.get(id)).filter(Boolean);
  if (memberKeys.length < QUORUM) return false;
  const message = new TextEncoder().encode(
    canonicalJson({ containerNumber: reading.containerNumber, celsius: reading.celsius, at: reading.at }),
  );
  const committeeKey = bls12_381.longSignatures.aggregatePublicKeys(memberKeys.map(hexToBytes));
  const point = bls12_381.longSignatures.hash(message, ORACLE_DST);
  const signature = hexToBytes(reading.signature);
  return bls12_381.longSignatures.verify(signature, point, committeeKey);
}

/**
 * @param {ColdChainReading} reading
 * @param {{ minCelsius: number, maxCelsius: number }} band
 */
export function excursion(reading, band) {
  if (reading.celsius < band.minCelsius) return { kind: 'too_cold', by: band.minCelsius - reading.celsius };
  if (reading.celsius > band.maxCelsius) return { kind: 'too_warm', by: reading.celsius - band.maxCelsius };
  return null;
}
