// Depot kiosk provisioning and pairing, used by the field engineers' console.
import { Router } from 'express';
import { sealField } from '../crypto/fieldCipher.js';
import { provisionKioskIdentity } from '../kiosks/kioskIdentity.js';
import { pairKiosk } from '../kiosks/pairing.js';
import { asyncHandler, badRequest, forbidden, notFoundError } from '../middleware/errors.js';
import { collection } from '../db/collections.js';

/**
 * @param {import('mongodb').Db} db
 */
export function kioskRoutes(db) {
  const router = Router();
  const kiosks = collection(db, 'kiosks');

  router.use((req, res, next) => {
    if (!req.session.supervisorId) next(forbidden('engineer_only'));
    else next();
  });

  router.post(
    '/',
    asyncHandler(async (req, res) => {
      const { id, depotCode, model } = req.body ?? {};
      if (typeof id !== 'string' || typeof model !== 'string') throw badRequest('kiosk_invalid');
      const provisioned = provisionKioskIdentity({ id, depotCode: String(depotCode), model });
      await kiosks.insertOne({
        _id: id,
        depotCode: provisioned.depotCode,
        model,
        identity: provisioned.identity,
        provisionedAt: provisioned.provisionedAt,
        pairedAt: null,
      });
      res.status(201).json({ kioskId: id, forSecureElement: provisioned.forSecureElement });
    }),
  );

  router.post(
    '/:kioskId/pair',
    asyncHandler(async (req, res) => {
      const kiosk = await kiosks.findOne({ _id: req.params.kioskId });
      if (!kiosk) throw notFoundError('kiosk');
      const depot = await collection(db, 'depots').findOne({ code: kiosk.depotCode });
      const tenant = await collection(db, 'tenants').findOne({ _id: depot.tenantId });
      const { gatewayPoint, confirmationCode, channelKey } = pairKiosk(String(req.body?.point ?? ''));
      await kiosks.updateOne(
        { _id: kiosk._id },
        {
          $set: {
            channelKey: sealField({ id: String(tenant._id), fieldSalt: tenant.fieldSalt.buffer }, channelKey.toString('base64')),
            pairedAt: new Date(),
          },
        },
      );
      res.json({ gatewayPoint, confirmationCode });
    }),
  );

  return router;
}
