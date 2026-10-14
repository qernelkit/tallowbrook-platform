// The relayer submits the shipper's release to FreightEscrow and records a signed
// release note that treasury reconciles against the chain.
import { Wallet } from 'ethers';
import { secret } from '../config.js';
import { chainProvider, freightEscrow, onChainShipmentId } from './escrowContract.js';
import { collection } from '../db/collections.js';

/** @type {Wallet | undefined} */
let relayerWallet;

function relayer() {
  relayerWallet ??= new Wallet(secret('ESCROW_RELAYER_KEY'), chainProvider());
  return relayerWallet;
}

/**
 * @param {import('mongodb').Db} db
 * @param {{ shipmentId: string, amountWei: bigint, shipperSignature: string }} release
 */
export async function submitRelease(db, release) {
  const signer = relayer();
  const releaseNote = `tallowbrook-release:${release.shipmentId}:${release.amountWei}`;
  const signature = await signer.signMessage(releaseNote);
  const tx = await freightEscrow(signer).release(onChainShipmentId(release.shipmentId), release.shipperSignature, {
    nonce: await signer.getNonce(),
  });
  await collection(db, 'releaseNotes').insertOne({
    shipmentId: release.shipmentId,
    note: releaseNote,
    relayer: signer.address,
    signature,
    txHash: tx.hash,
    submittedAt: new Date(),
  });
  return tx.hash;
}
