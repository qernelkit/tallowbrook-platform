import { randomBytes, randomUUID } from 'node:crypto';
import { Router } from 'express';
import { sealField, openField } from '../crypto/fieldCipher.js';
import { newVaultKey, sealRouteBundle } from '../drivers/offlineVault.js';
import { parsePhoneKey, sealPairingGrant } from '../drivers/pairing.js';
import { checkDriverPin, hashDriverPin, pinProblem } from '../drivers/pinStore.js';
import { evaluateHoldListQuery, withinQuota } from '../privacy/holdListMatching.js';
import { asyncHandler, badRequest, forbidden, notFoundError, unauthorized } from '../middleware/errors.js';
import { collection } from '../db/collections.js';

/**
 * @param {import('mongodb').Db} db
 */
export function driverRoutes(db) {
  const router = Router();
  const drivers = collection(db, 'drivers');
  const devices = collection(db, 'driverDevices');

  /**
   * @param {any} driver
   */
  const tenantOf = async (driver) => {
    const tenant = await collection(db, 'tenants').findOne({ _id: driver.tenantId });
    return { id: String(tenant._id), fieldSalt: tenant.fieldSalt.buffer };
  };

  // Called by the depot supervisor's console after scanning the phone's QR code.
  router.post(
    '/:driverId/devices',
    asyncHandler(async (req, res) => {
      if (!req.session.supervisorId) throw forbidden('supervisor_only');
      const driver = await drivers.findOne({ _id: req.params.driverId, active: true });
      if (!driver) throw notFoundError('driver');
      const phoneKey = parsePhoneKey(String(req.body?.phoneKey ?? ''));
      const deviceId = `dev_${randomUUID()}`;
      const vaultKey = Buffer.from(newVaultKey());
      const refreshToken = randomBytes(32).toString('base64url');
      const tenant = await tenantOf(driver);
      await devices.insertOne({
        _id: deviceId,
        driverId: driver._id,
        tenantId: driver.tenantId,
        vaultKey: sealField(tenant, vaultKey.toString('base64')),
        refreshToken: sealField(tenant, refreshToken),
        pairedBy: req.session.supervisorId,
        pairedAt: new Date(),
        revokedAt: null,
      });
      res
        .status(201)
        .json(sealPairingGrant(phoneKey, { driverId: String(driver._id), deviceId, vaultKey: vaultKey.toString('base64'), refreshToken }));
    }),
  );

  router.put(
    '/:driverId/pin',
    asyncHandler(async (req, res) => {
      if (!req.session.supervisorId) throw forbidden('supervisor_only');
      const pin = String(req.body?.pin ?? '');
      const problem = pinProblem(pin);
      if (problem) throw badRequest('pin_rejected', { pin: problem });
      await drivers.updateOne({ _id: req.params.driverId }, { $set: { pinHash: await hashDriverPin(pin), pinChangedAt: new Date() } });
      res.status(204).end();
    }),
  );

  router.post(
    '/:driverId/shift',
    asyncHandler(async (req, res) => {
      const driver = await drivers.findOne({ _id: req.params.driverId, active: true });
      if (!driver?.pinHash || !(await checkDriverPin(String(req.body?.pin ?? ''), driver.pinHash))) throw unauthorized('pin_wrong');
      await collection(db, 'shifts').insertOne({ driverId: driver._id, depot: req.body.depot, startedAt: new Date() });
      res.status(201).json({ started: true });
    }),
  );

  router.get(
    '/:driverId/devices/:deviceId/route-bundle',
    asyncHandler(async (req, res) => {
      const device = await devices.findOne({ _id: req.params.deviceId, driverId: req.params.driverId, revokedAt: null });
      if (!device) throw notFoundError('device');
      const driver = await drivers.findOne({ _id: device.driverId });
      const tenant = await tenantOf(driver);
      const vaultKey = new Uint8Array(Buffer.from(openField(tenant, device.vaultKey), 'base64'));
      const date = new Date().toISOString().slice(0, 10);
      const route = await collection(db, 'routes').findOne({ driverId: device.driverId, date });
      if (!route) throw notFoundError('route');
      res.json(sealRouteBundle({ routeId: String(route._id), driverId: String(device.driverId), date, stops: route.stops }, vaultKey));
    }),
  );

  router.post(
    '/:driverId/hold-list/query',
    asyncHandler(async (req, res) => {
      if (!withinQuota(req.params.driverId)) {
        res.status(429).json({ error: 'quota_exceeded' });
        return;
      }
      res.json({ evaluated: evaluateHoldListQuery(String(req.body?.query ?? '')) });
    }),
  );

  return router;
}
