import { randomUUID } from 'node:crypto';
import { Router } from 'express';
import { sessionTokenAuth } from '../auth/sessionTokens.js';
import { sealField } from '../crypto/fieldCipher.js';
import { signedPhotoUrl } from '../links/mediaCdn.js';
import { asyncHandler, badRequest, notFoundError } from '../middleware/errors.js';
import { collection } from '../db/collections.js';

const CLAIM_REASONS = ['damaged', 'missing_items', 'not_delivered', 'late'];
const MAX_PHOTOS = 8;

/**
 * @param {any} body
 */
function claimErrors(body) {
  const errors = {};
  if (!CLAIM_REASONS.includes(body?.reason)) errors.reason = `one of ${CLAIM_REASONS.join(', ')}`;
  if (typeof body?.description !== 'string' || body.description.trim().length < 20) errors.description = 'at least 20 characters';
  if (!(Number(body?.amountMinor) > 0)) errors.amountMinor = 'positive amount';
  return errors;
}

/**
 * @param {import('mongodb').Db} db
 */
export function claimRoutes(db) {
  const router = Router();
  const claims = collection(db, 'claims');
  router.use(sessionTokenAuth);

  router.post(
    '/',
    asyncHandler(async (req, res) => {
      const errors = claimErrors(req.body);
      if (Object.keys(errors).length) throw badRequest('claim_invalid', errors);
      const shipment = await collection(db, 'shipments').findOne({ _id: req.body.shipmentId, accountId: res.locals.session.sub });
      if (!shipment) throw notFoundError('shipment');
      const tenant = await collection(db, 'tenants').findOne({ _id: shipment.tenantId });
      const id = `clm_${randomUUID()}`;
      await claims.insertOne({
        _id: id,
        shipmentId: shipment._id,
        tenantId: shipment.tenantId,
        reason: req.body.reason,
        description: sealField({ id: String(tenant._id), fieldSalt: tenant.fieldSalt.buffer }, req.body.description.trim()),
        amountMinor: Number(req.body.amountMinor),
        photos: [],
        status: 'open',
        createdAt: new Date(),
      });
      res.status(201).json({ id, status: 'open' });
    }),
  );

  router.post(
    '/:id/photos',
    asyncHandler(async (req, res) => {
      const claim = await claims.findOne({ _id: req.params.id, status: 'open' });
      if (!claim) throw notFoundError('open claim');
      if (claim.photos.length >= MAX_PHOTOS) throw badRequest('too_many_photos');
      const objectKey = `claims/${claim._id}/${randomUUID()}.jpg`;
      await claims.updateOne({ _id: claim._id }, /** @type {any} */ ({ $push: { photos: { objectKey, addedAt: new Date() } } }));
      res.status(201).json({ objectKey, uploadUrl: `/v1/claims/${claim._id}/photos/${encodeURIComponent(objectKey)}` });
    }),
  );

  router.get(
    '/:id/delivery-photos',
    asyncHandler(async (req, res) => {
      const claim = await claims.findOne({ _id: req.params.id });
      if (!claim) throw notFoundError('claim');
      const pod = await collection(db, 'proofOfDelivery').findOne({ shipmentId: claim.shipmentId });
      const keys = pod?.photoKeys ?? [];
      res.json({ photos: keys.map((key) => ({ key, url: signedPhotoUrl(key) })) });
    }),
  );

  return router;
}
