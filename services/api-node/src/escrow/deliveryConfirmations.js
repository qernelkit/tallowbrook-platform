// Couriers without their own wallet use a custodial one held by the gateway. When the
// driver app reports a delivery with the consignee's PIN, the gateway signs the
// Delivery struct for FreightEscrow.confirmDelivery on the courier's behalf.
import { Wallet, encodeBytes32String } from 'ethers';
import { config } from '../config.js';
import { openField } from '../crypto/fieldCipher.js';
import { chainProvider, freightEscrow, onChainShipmentId } from './escrowContract.js';

export const ESCROW_DOMAIN = {
  name: 'Tallowbrook Freight Escrow',
  version: '1',
  chainId: config.escrow.chainId,
  verifyingContract: config.escrow.contractAddress,
};

export const DELIVERY_TYPES = {
  Delivery: [
    { name: 'shipmentId', type: 'uint256' },
    { name: 'courier', type: 'address' },
    { name: 'deliveredAt', type: 'uint64' },
  ],
};

/**
 * @param {{ id: string, fieldSalt: Buffer }} tenant
 * @param {{ sealedKey: string }} custody
 */
function courierWalletFor(tenant, custody) {
  return new Wallet(openField(tenant, custody.sealedKey), chainProvider());
}

/**
 * @param {{ id: string, fieldSalt: Buffer }} tenant
 * @param {{ sealedKey: string }} custody
 * @param {{ shipmentId: string, deliveredAt: Date, pin: string, salt: string }} report
 */
export async function confirmDelivery(tenant, custody, report) {
  const courierWallet = courierWalletFor(tenant, custody);
  const delivery = {
    shipmentId: onChainShipmentId(report.shipmentId),
    courier: courierWallet.address,
    deliveredAt: BigInt(Math.floor(report.deliveredAt.getTime() / 1000)),
  };
  const signature = await courierWallet.signTypedData(ESCROW_DOMAIN, DELIVERY_TYPES, delivery);
  const tx = await freightEscrow(courierWallet).confirmDelivery(
    delivery.shipmentId,
    delivery.deliveredAt,
    encodeBytes32String(report.pin),
    report.salt,
    signature,
  );
  return tx.hash;
}
