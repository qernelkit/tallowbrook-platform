// Partner API (/v1/partners): customs brokers, cold-chain providers and payment
// partners call it with tokens issued by their own identity providers.
import { Router } from 'express';
import { verifyPartnerToken } from '../auth/partnerTokens.js';
import { readingIsAttested, excursion } from '../coldchain/oracleAttestations.js';
import { declarationProblems, envelopeDeclaration } from '../customs/declarationEnvelope.js';
import { asyncHandler, badRequest, forbidden, unauthorized } from '../middleware/errors.js';
import { signDeliveryReceipt } from '../receipts/receiptSigner.js';
import { collection } from '../db/collections.js';

/**
 * @param {string[]} scopes
 * @param {string} needed
 */
function requireScope(scopes, needed) {
  if (!scopes.includes(needed)) throw forbidden(`scope_${needed.replace(/[:.]/g, '_')}_missing`);
}

/**
 * @param {import('mongodb').Db} db
 */
export function partnerRoutes(db) {
  const router = Router();

  router.use((req, res, next) => {
    const header = req.get('authorization') ?? '';
    if (!header.startsWith('Bearer ')) {
      next(unauthorized());
      return;
    }
    verifyPartnerToken(header.slice('Bearer '.length)).then(
      (partner) => {
        res.locals.partner = partner;
        next();
      },
      () => next(unauthorized('partner_token_invalid')),
    );
  });

  router.post(
    '/customs/declarations',
    asyncHandler(async (req, res) => {
      requireScope(res.locals.partner.scopes, 'customs:declare');
      const problems = declarationProblems(req.body);
      if (problems.length) throw badRequest('declaration_invalid', { fields: problems.join(', ') });
      const sealedDeclaration = await envelopeDeclaration(req.body);
      await collection(db, 'declarations').insertOne({
        shipmentId: req.body.shipmentId,
        partnerId: res.locals.partner.partnerId,
        sealedDeclaration,
        sentAt: new Date(),
      });
      res.status(202).json({ shipmentId: req.body.shipmentId, queued: true });
    }),
  );

  router.post(
    '/coldchain/readings',
    asyncHandler(async (req, res) => {
      requireScope(res.locals.partner.scopes, 'coldchain:report');
      const committee = new Map((await collection(db, 'oracleMembers').find({ active: true }).toArray()).map((m) => [m._id, m.blsKeyHex]));
      if (!readingIsAttested(req.body, committee)) throw badRequest('reading_not_attested');
      const container = await collection(db, 'reeferContainers').findOne({ containerNumber: req.body.containerNumber });
      const out = container ? excursion(req.body, container.band) : null;
      await collection(db, 'coldchainReadings').insertOne({ ...req.body, excursion: out, receivedAt: new Date() });
      res.status(201).json({ excursion: out });
    }),
  );

  router.get(
    '/receipts/:shipmentId',
    asyncHandler(async (req, res) => {
      requireScope(res.locals.partner.scopes, 'receipts:read');
      const pod = await collection(db, 'proofOfDelivery').findOne({ shipmentId: req.params.shipmentId });
      if (!pod) {
        res.status(404).json({ error: 'not_delivered' });
        return;
      }
      res.json(
        signDeliveryReceipt({
          shipmentId: req.params.shipmentId,
          deliveredAt: pod.deliveredAt.toISOString(),
          receivedBy: pod.receivedBy,
          depot: pod.depot,
        }),
      );
    }),
  );

  return router;
}
