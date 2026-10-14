// Nightly jobs, run by the scheduler pod with `node src/jobs/nightly.js <job>`.
import { buildIftmin } from '../carriers/iftminMessage.js';
import { CARRIER_PROFILES, carrierProfile } from '../carriers/carrierProfiles.js';
import { buildManifestFile, manifestFileName } from '../carriers/manifestExport.js';
import { exportMonthlyArchive } from '../customs/archiveExport.js';
import { connectMongo } from '../db/mongo.js';
import { signSettlementBatch } from '../escrow/hotWallet.js';
import { logger } from '../logger.js';
import { signCustomsManifest } from '../manifests/manifestSigner.js';
import { sealForRecipient } from '../partners/pqEnvelope.js';
import { instructionProblems, wrapForHarborPay } from '../partners/dataKeyWrap.js';
import { postInternal } from '../tls/upstreamAgent.js';
import { config } from '../config.js';
import { collection } from '../db/collections.js';

/**
 * @param {import('mongodb').Db} db
 * @param {Date} day
 */
async function carrierManifests(db, day) {
  for (const carrierId of Object.keys(CARRIER_PROFILES)) {
    const profile = carrierProfile(carrierId);
    const lines = await collection(db, 'manifestLines')
      .find({ carrierId, day: day.toISOString().slice(0, 10) })
      .toArray();
    if (lines.length === 0) continue;
    if (profile.manifestFormat === 'edifact') {
      let controlRef = Number((await collection(db, 'counters').findOne({ _id: `edi:${carrierId}` }))?.value ?? 0);
      for (const booking of lines) {
        controlRef += 1;
        await collection(db, 'outbox').insertOne({
          carrierId,
          kind: 'iftmin',
          body: buildIftmin(booking, controlRef, day),
          createdAt: new Date(),
        });
      }
      await collection(db, 'counters').updateOne({ _id: `edi:${carrierId}` }, { $set: { value: controlRef } }, { upsert: true });
      continue;
    }
    const file = buildManifestFile(carrierId, lines);
    await collection(db, 'outbox').insertOne({
      carrierId,
      kind: 'manifest',
      name: manifestFileName(carrierId, day),
      body: file,
      createdAt: new Date(),
    });
    logger.info({ carrierId, lines: lines.length }, 'manifest queued');
  }
}

/**
 * @param {import('mongodb').Db} db
 * @param {Date} day
 */
async function customsArchive(db, day) {
  if (day.getUTCDate() !== 1) return;
  const previous = new Date(Date.UTC(day.getUTCFullYear(), day.getUTCMonth() - 1, 1));
  const month = previous.toISOString().slice(0, 7);
  const entries = await collection(db, 'customsEntries').find({ month }).toArray();
  const { fileName, armored } = await exportMonthlyArchive(month, entries);
  await collection(db, 'outbox').insertOne({
    partner: 'harbor-customs',
    kind: 'archive',
    name: fileName,
    body: armored,
    createdAt: new Date(),
  });
}

/**
 * @param {import('mongodb').Db} db
 */
async function customsPilot(db) {
  const manifests = await collection(db, 'customsManifests').find({ pilot: true, sentAt: null }).limit(200).toArray();
  for (const manifest of manifests) {
    const { signature } = signCustomsManifest(manifest);
    const sealedBundle = sealForRecipient('harbor-customs', { manifest, signature });
    await collection(db, 'outbox').insertOne({
      partner: 'harbor-customs',
      kind: 'pre-clearance',
      body: sealedBundle,
      createdAt: new Date(),
    });
    await collection(db, 'customsManifests').updateOne({ _id: manifest._id }, { $set: { sentAt: new Date() } });
  }
}

/**
 * @param {import('mongodb').Db} db
 * @param {Date} day
 */
async function settlements(db, day) {
  const payouts = await collection(db, 'courierPayouts').find({ settledAt: null }).toArray();
  if (payouts.length === 0) return;
  const batch = {
    batchId: `SB-${day.toISOString().slice(0, 10).replace(/-/g, '')}`,
    payouts: payouts.map((p) => ({ courier: p.courierAddress, amountWei: String(p.amountWei) })),
  };
  await postInternal(`${config.upstream.ledgerUrl}/settlement-batches`, { ...batch, signature: signSettlementBatch(batch) });
  const instructions = await collection(db, 'harborPayInstructions').find({ sentAt: null }).toArray();
  for (const instruction of instructions) {
    if (instructionProblems(instruction).length) {
      logger.warn({ instructionId: instruction.instructionId }, 'skipping malformed settlement instruction');
      continue;
    }
    await collection(db, 'outbox').insertOne({
      partner: 'harbor-pay',
      kind: 'instruction',
      body: wrapForHarborPay(instruction),
      createdAt: new Date(),
    });
  }
}

const JOBS = { carrierManifests, customsArchive, customsPilot, settlements };

async function main() {
  const name = process.argv[2];
  const job = JOBS[name];
  if (!job) {
    console.error(`usage: nightly.js <${Object.keys(JOBS).join('|')}>`);
    process.exit(2);
  }
  const db = await connectMongo();
  const day = new Date();
  await job(db, day);
  logger.info({ job: name }, 'job finished');
  process.exit(0);
}

if (process.argv[1] && import.meta.url.endsWith(process.argv[1].split('/').pop())) {
  main().catch((err) => {
    logger.fatal({ err }, 'job failed');
    process.exit(1);
  });
}
