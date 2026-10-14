import express from 'express';
import { installSessions } from './middleware/session.js';
import { catalogueEtag } from './middleware/etag.js';
import { requestId } from './middleware/requestId.js';
import { errorHandler, notFound } from './middleware/errors.js';
import { RouteRegistry } from './routes/registry.js';
import { accountRoutes } from './routes/account.js';
import { carrierHookRoutes } from './routes/carrierHooks.js';
import { claimRoutes } from './routes/claims.js';
import { driverRoutes } from './routes/drivers.js';
import { escrowRoutes } from './routes/escrow.js';
import { healthRoutes } from './routes/health.js';
import { kioskRoutes } from './routes/kiosks.js';
import { labelRoutes } from './routes/labels.js';
import { partnerRoutes } from './routes/partners.js';
import { quoteRoutes } from './routes/quotes.js';
import { shipmentRoutes } from './routes/shipments.js';

/**
 * @param {import('mongodb').Db} db
 */
export function createApp(db) {
  const app = express();
  app.disable('x-powered-by');
  app.set('etag', false);
  app.set('trust proxy', 1);

  app.use(requestId);
  // Webhook receivers need the raw body; everything else is JSON.
  app.use('/hooks', express.raw({ type: '*/*', limit: '1mb' }));
  app.use(express.json({ limit: '256kb' }));
  installSessions(app, db);

  const registry = new RouteRegistry(app);
  registry.mount('/health', healthRoutes());
  registry.mount('/v1/account', accountRoutes(db));
  registry.mount('/v1/shipments', shipmentRoutes(db));
  registry.mount('/v1/quotes', quoteRoutes());
  registry.mount('/v1/labels', labelRoutes(db));
  registry.mount('/v1/claims', claimRoutes(db));
  registry.mount('/v1/drivers', driverRoutes(db));
  registry.mount('/v1/escrow', escrowRoutes(db));
  registry.mount('/v1/kiosks', kioskRoutes(db));
  registry.mount('/v1/partners', partnerRoutes(db));
  registry.mount('/hooks', carrierHookRoutes(db));
  app.use('/v1/catalogue', catalogueEtag);

  app.use(notFound);
  app.use(errorHandler);
  return app;
}
