// FreightEscrow (contracts/src/FreightEscrow.sol) as seen from the gateway.
import { Contract, JsonRpcProvider } from 'ethers';
import { config } from '../config.js';

export const FREIGHT_ESCROW_ABI = [
  'function deposit(uint256 shipmentId, address courier, uint64 deadline) payable',
  'function commitPin(uint256 shipmentId, bytes32 commitment)',
  'function confirmDelivery(uint256 shipmentId, uint64 deliveredAt, bytes32 pinCode, bytes32 salt, bytes courierSignature)',
  'function release(uint256 shipmentId, bytes shipperSignature)',
  'function refund(uint256 shipmentId)',
  'function shipmentStatus(uint256 shipmentId) view returns (uint8)',
  'event Deposited(uint256 indexed shipmentId, address indexed shipper, uint256 amount)',
  'event DeliveryConfirmed(uint256 indexed shipmentId, address indexed courier, uint64 deliveredAt)',
  'event Released(uint256 indexed shipmentId, address indexed courier, uint256 amount)',
];

export const SHIPMENT_STATUS = ['none', 'funded', 'delivered', 'released', 'refunded'];

/** @type {JsonRpcProvider | undefined} */
let provider;

export function chainProvider() {
  provider ??= new JsonRpcProvider(config.escrow.rpcUrl, config.escrow.chainId, { staticNetwork: true });
  return provider;
}

/**
 * @param {import('ethers').ContractRunner} [runner]
 */
export function freightEscrow(runner = chainProvider()) {
  return new Contract(config.escrow.contractAddress, FREIGHT_ESCROW_ABI, runner);
}

/**
 * Shipment ids on chain are the numeric part of our public shipment id.
 * @param {string} shipmentId e.g. shp_000123456
 */
export function onChainShipmentId(shipmentId) {
  const match = /^shp_(\d{9})$/.exec(shipmentId);
  if (!match) throw new Error(`not an escrow shipment id: ${shipmentId}`);
  return BigInt(match[1]);
}
