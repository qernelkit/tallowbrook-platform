// Gateway entry point: opens Mongo, builds the Express app and starts the listener.
import https from 'node:https';
import { config } from './config.js';
import { createApp } from './app.js';
import { connectMongo } from './db/mongo.js';
import { logger } from './logger.js';
import { listenerOptions } from './tls/listenerOptions.js';

async function main() {
  const db = await connectMongo();
  const app = createApp(db);
  const server = https.createServer(listenerOptions(config), app);

  server.listen(config.listen.port, config.listen.host, () => {
    logger.info({ port: config.listen.port }, 'gateway listening');
  });

  let stopping = false;
  const stop = (signal) => {
    if (stopping) return;
    stopping = true;
    logger.info({ signal }, 'draining connections');
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(1), config.listen.shutdownGraceMs).unref();
  };
  process.on('SIGTERM', stop);
  process.on('SIGINT', stop);
}

main().catch((err) => {
  logger.fatal({ err }, 'gateway failed to start');
  process.exit(1);
});
