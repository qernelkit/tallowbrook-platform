// Inbound webhooks and callbacks from carriers and partners. Bodies arrive raw (see
// app.js) because every scheme here authenticates the exact bytes.
import { Router } from 'express';
import { secret } from '../config.js';
import { normaliseStatus, statusSignatureValid } from '../carriers/statusWebhooks.js';
import tracking from '../carriers/trackingCallbacks.cjs';
import harborPay from '../webhooks/partnerWebhooks.cjs';
import { partnerCallbackValid } from '../partners/callbackAuth.js';
import { childLogger } from '../logger.js';
import { asyncHandler, notFoundError, unauthorized } from '../middleware/errors.js';
import { collection } from '../db/collections.js';

const log = childLogger('hooks');

/**
 * @param {import('mongodb').Db} db
 */
export function carrierHookRoutes(db) {
  const router = Router();
  const carriers = collection(db, 'carriers');
  const events = collection(db, 'trackingEvents');

  router.post(
    '/carriers/:carrierId/status',
    asyncHandler(async (req, res) => {
      const carrier = await carriers.findOne({ _id: req.params.carrierId, active: true });
      if (!carrier) throw notFoundError('carrier');
      if (!statusSignatureValid(carrier, req.body, req.get('x-carrier-signature'))) throw unauthorized('bad_carrier_signature');
      const status = normaliseStatus(JSON.parse(req.body.toString('utf8')));
      if (!status) {
        res.status(202).json({ ignored: true });
        return;
      }
      await events.insertOne({ carrierId: carrier._id, ...status, receivedAt: new Date() });
      res.status(204).end();
    }),
  );

  router.post(
    '/carriers/:carrierId/tracking',
    tracking.trackingCallbackHandler(
      (carrierId) => carriers.findOne({ _id: carrierId, active: true, integration: '2017' }),
      async (event, carrierId) => {
        await events.insertOne({ carrierId, ...event, receivedAt: new Date() });
      },
    ),
  );

  router.post(
    '/partners/harbor-pay',
    harborPay.harborPayWebhook(log, async (event) => {
      await collection(db, 'settlementEvents').insertOne({ partner: 'harbor-pay', event, receivedAt: new Date() });
    }),
  );

  router.post(
    '/partners/:partnerId/callback',
    asyncHandler(async (req, res) => {
      const partnerId = req.params.partnerId;
      if (!/^[a-z-]{3,32}$/.test(partnerId)) throw notFoundError('partner');
      const callbackSecret = Buffer.from(secret(`PARTNER_CALLBACK_${partnerId.toUpperCase().replace(/-/g, '_')}`), 'base64');
      if (!(await partnerCallbackValid(partnerId, callbackSecret, req.body, req.get('x-partner-mac'))))
        throw unauthorized('bad_partner_mac');
      await collection(db, 'partnerCallbacks').insertOne({ partnerId, body: req.body.toString('utf8'), receivedAt: new Date() });
      res.status(204).end();
    }),
  );

  return router;
}
