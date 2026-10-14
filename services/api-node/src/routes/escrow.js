import { Router } from 'express';
import { sessionTokenAuth } from '../auth/sessionTokens.js';
import { openDepositWallet } from '../escrow/depositWallets.js';
import { confirmDelivery } from '../escrow/deliveryConfirmations.js';
import { newDeliveryCommitment } from '../escrow/deliveryCommitments.js';
import { submitRelease } from '../escrow/releaseAttestations.js';
import { SHIPMENT_STATUS, freightEscrow, onChainShipmentId } from '../escrow/escrowContract.js';
import { asyncHandler, badRequest, notFoundError } from '../middleware/errors.js';
import { collection } from '../db/collections.js';

/**
 * @param {import('mongodb').Db} db
 */
export function escrowRoutes(db) {
  const router = Router();
  router.use(sessionTokenAuth);

  /**
   * @param {string} shipmentId
   * @param {string} accountId
   */
  const ownedShipment = async (shipmentId, accountId) => {
    const shipment = await collection(db, 'shipments').findOne({ _id: shipmentId, accountId, escrow: true });
    if (!shipment) throw notFoundError('escrow shipment');
    return shipment;
  };

  router.get(
    '/:shipmentId',
    asyncHandler(async (req, res) => {
      await ownedShipment(req.params.shipmentId, res.locals.session.sub);
      const status = await freightEscrow().shipmentStatus(onChainShipmentId(req.params.shipmentId));
      res.json({ shipmentId: req.params.shipmentId, status: SHIPMENT_STATUS[Number(status)] ?? 'unknown' });
    }),
  );

  router.post(
    '/:shipmentId/deposit-address',
    asyncHandler(async (req, res) => {
      const shipment = await ownedShipment(req.params.shipmentId, res.locals.session.sub);
      const tenant = await collection(db, 'tenants').findOne({ _id: shipment.tenantId });
      const address = await openDepositWallet(db, { id: String(tenant._id), fieldSalt: tenant.fieldSalt.buffer }, shipment._id);
      res.json({ address });
    }),
  );

  // Shipper side, at pickup: the PIN goes to the consignee, the commitment on chain.
  router.post(
    '/:shipmentId/delivery-pin',
    asyncHandler(async (req, res) => {
      const shipment = await ownedShipment(req.params.shipmentId, res.locals.session.sub);
      if (!shipment.courierAddress) throw badRequest('no_courier_assigned');
      const pin = String(req.body?.pin ?? '');
      const { salt, commitment } = newDeliveryCommitment(pin, shipment.courierAddress);
      await collection(db, 'shipments').updateOne({ _id: shipment._id }, { $set: { pinSalt: salt, pinCommitment: commitment } });
      res.json({ commitment });
    }),
  );

  // Driver app, at the door.
  router.post(
    '/:shipmentId/delivered',
    asyncHandler(async (req, res) => {
      const shipment = await collection(db, 'shipments').findOne({ _id: req.params.shipmentId, escrow: true });
      if (!shipment?.pinSalt) throw notFoundError('escrow shipment');
      const custody = await collection(db, 'courierWallets').findOne({ address: shipment.courierAddress });
      if (!custody) throw badRequest('courier_wallet_not_custodial');
      const tenant = await collection(db, 'tenants').findOne({ _id: custody.tenantId });
      const txHash = await confirmDelivery({ id: String(tenant._id), fieldSalt: tenant.fieldSalt.buffer }, custody, {
        shipmentId: shipment._id,
        deliveredAt: new Date(),
        pin: String(req.body?.pin ?? ''),
        salt: shipment.pinSalt,
      });
      res.status(202).json({ txHash });
    }),
  );

  router.post(
    '/:shipmentId/release',
    asyncHandler(async (req, res) => {
      const shipment = await ownedShipment(req.params.shipmentId, res.locals.session.sub);
      if (typeof req.body?.shipperSignature !== 'string') throw badRequest('signature_missing');
      const txHash = await submitRelease(db, {
        shipmentId: shipment._id,
        amountWei: BigInt(shipment.escrowAmountWei),
        shipperSignature: req.body.shipperSignature,
      });
      res.status(202).json({ txHash });
    }),
  );

  return router;
}
