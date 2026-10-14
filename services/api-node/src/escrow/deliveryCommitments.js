// At pickup the shipper commits to the consignee's delivery PIN. The commitment must
// match FreightEscrow.confirmDelivery, which checks
// keccak256(abi.encodePacked(pinCode, salt, courier)).
import { encodeBytes32String, hexlify, randomBytes, solidityPackedKeccak256 } from 'ethers';

/**
 * @param {string} pin four to eight digits, given to the consignee by SMS
 * @param {string} courier courier wallet address
 */
export function newDeliveryCommitment(pin, courier) {
  if (!/^\d{4,8}$/.test(pin)) throw new Error('delivery PIN must be 4 to 8 digits');
  const salt = hexlify(randomBytes(32));
  return { salt, commitment: deliveryPinCommitment(encodeBytes32String(pin), salt, courier) };
}

/**
 * @param {string} pinCode bytes32
 * @param {string} salt bytes32
 * @param {string} courier address
 */
export function deliveryPinCommitment(pinCode, salt, courier) {
  return solidityPackedKeccak256(['bytes32', 'bytes32', 'address'], [pinCode, salt, courier]);
}
