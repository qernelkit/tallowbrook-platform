import { Router } from 'express';
import { config } from '../config.js';

const startedAt = new Date();

export function healthRoutes() {
  const router = Router();
  router.get('/live', (req, res) => {
    res.json({ status: 'ok' });
  });
  router.get('/ready', (req, res) => {
    res.json({
      status: 'ok',
      service: config.service,
      env: config.env,
      startedAt: startedAt.toISOString(),
      uptimeSeconds: Math.round(process.uptime()),
    });
  });
  return router;
}
