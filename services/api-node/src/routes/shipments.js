import { randomInt } from 'node:crypto';
import { Router } from 'express';
import { sessionTokenAuth } from '../auth/sessionTokens.js';
import { sealField } from '../crypto/fieldCipher.js';
import { publicOrderId } from '../ids/orderHashids.js';
import { asyncHandler, badRequest, notFoundError } from '../middleware/errors.js';
import { totalWeightGrams, validateBooking } from '../validation/shipment.js';
import { collection } from '../db/collections.js';

const PAGE_SIZE = 25;

/**
 * @param {import('mongodb').Db} db
 */
export function shipmentRoutes(db) {
  const router = Router();
  const shipments = collection(db, 'shipments');
  router.use(sessionTokenAuth);

  router.get(
    '/',
    asyncHandler(async (req, res) => {
      const page = Math.max(1, Number(req.query.page ?? 1));
      const filter = { accountId: res.locals.session.sub };
      if (typeof req.query.status === 'string') filter.status = req.query.status;
      const items = await shipments
        .find(filter, { projection: { deliveryNote: 0 } })
        .sort({ createdAt: -1 })
        .skip((page - 1) * PAGE_SIZE)
        .limit(PAGE_SIZE)
        .toArray();
      res.json({ page, items });
    }),
  );

  router.get(
    '/:id',
    asyncHandler(async (req, res) => {
      const shipment = await shipments.findOne(
        { _id: req.params.id, accountId: res.locals.session.sub },
        { projection: { deliveryNote: 0 } },
      );
      if (!shipment) throw notFoundError('shipment');
      res.json(shipment);
    }),
  );

  router.post(
    '/',
    asyncHandler(async (req, res) => {
      const errors = validateBooking(req.body);
      if (Object.keys(errors).length > 0) throw badRequest('booking_invalid', errors);
      const account = await collection(db, 'accounts').findOne({ _id: res.locals.session.sub });
      const tenant = await collection(db, 'tenants').findOne({ _id: account.tenantId });
      const orderNumber = await nextOrderNumber(db);
      const id = `shp_${String(randomInt(1e9)).padStart(9, '0')}`;
      const doc = {
        _id: id,
        orderNumber,
        publicId: publicOrderId(orderNumber),
        accountId: account._id,
        tenantId: tenant._id,
        service: req.body.service,
        sender: req.body.sender,
        consignee: req.body.consignee,
        parcels: req.body.parcels,
        totalWeightGrams: totalWeightGrams(req.body),
        deliveryNote: req.body.deliveryNote
          ? sealField({ id: String(tenant._id), fieldSalt: tenant.fieldSalt.buffer }, req.body.deliveryNote)
          : null,
        status: 'booked',
        createdAt: new Date(),
      };
      await shipments.insertOne(doc);
      res.status(201).json({ id, publicId: doc.publicId, status: doc.status });
    }),
  );

  router.post(
    '/:id/cancel',
    asyncHandler(async (req, res) => {
      const result = await shipments.updateOne(
        { _id: req.params.id, accountId: res.locals.session.sub, status: { $in: ['booked', 'awaiting_collection'] } },
        { $set: { status: 'cancelled', cancelledAt: new Date() } },
      );
      if (result.matchedCount === 0) throw notFoundError('cancellable shipment');
      res.status(204).end();
    }),
  );

  return router;
}

/**
 * @param {import('mongodb').Db} db
 * @returns {Promise<number>}
 */
async function nextOrderNumber(db) {
  const counter = await collection(db, 'counters').findOneAndUpdate(
    { _id: 'orderNumber' },
    { $inc: { value: 1 } },
    { upsert: true, returnDocument: 'after' },
  );
  return counter.value;
}
