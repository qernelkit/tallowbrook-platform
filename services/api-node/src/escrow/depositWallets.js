// Shippers who pay by card fund escrow through a deposit address per shipment. The
// payments service tops the address up and the gateway forwards the deposit.
import { Wallet } from 'ethers';
import { sealField } from '../crypto/fieldCipher.js';
import { collection } from '../db/collections.js';

/**
 * @param {import('mongodb').Db} db
 * @param {{ id: string, fieldSalt: Buffer }} tenant
 * @param {string} shipmentId
 * @returns {Promise<string>} the deposit address
 */
export async function openDepositWallet(db, tenant, shipmentId) {
  const existing = await collection(db, 'depositWallets').findOne({ shipmentId });
  if (existing) return existing.address;
  const wallet = Wallet.createRandom();
  await collection(db, 'depositWallets').insertOne({
    shipmentId,
    tenantId: tenant.id,
    address: wallet.address,
    sealedKey: sealField(tenant, wallet.privateKey),
    createdAt: new Date(),
    sweptAt: null,
  });
  return wallet.address;
}
