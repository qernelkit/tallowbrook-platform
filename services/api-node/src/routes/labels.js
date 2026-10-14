import { Router } from 'express';
import { sessionTokenAuth } from '../auth/sessionTokens.js';
import { checkLabelLink, signedLabelUrl } from '../links/downloadLinks.js';
import { asyncHandler, forbidden, notFoundError } from '../middleware/errors.js';
import { collection } from '../db/collections.js';

const FORMATS = new Set(['a6', '4x6']);

/**
 * @param {import('mongodb').Db} db
 */
export function labelRoutes(db) {
  const router = Router();
  const shipments = collection(db, 'shipments');

  // The web app asks for a link; the label printer fetches it without credentials.
  router.post(
    '/:shipmentId/link',
    sessionTokenAuth,
    asyncHandler(async (req, res) => {
      const format = FORMATS.has(req.body?.format) ? req.body.format : 'a6';
      const shipment = await shipments.findOne(
        { _id: req.params.shipmentId, accountId: res.locals.session.sub },
        { projection: { _id: 1 } },
      );
      if (!shipment) throw notFoundError('shipment');
      res.json({ url: signedLabelUrl(req.params.shipmentId, format) });
    }),
  );

  router.get(
    '/:file',
    asyncHandler(async (req, res) => {
      const match = /^(shp_\d{9})\.(a6|4x6)\.pdf$/.exec(req.params.file);
      if (!match) throw notFoundError('label');
      const verdict = checkLabelLink(`/v1/labels/${req.params.file}`, String(req.query.expires ?? ''), String(req.query.sig ?? ''));
      if (verdict !== 'ok') throw forbidden(`label_link_${verdict}`);
      const label = await collection(db, 'labels').findOne({ shipmentId: match[1], format: match[2] });
      if (!label) throw notFoundError('label');
      res.type('application/pdf');
      res.setHeader('Cache-Control', 'private, no-store');
      res.send(label.pdf.buffer);
    }),
  );

  return router;
}
