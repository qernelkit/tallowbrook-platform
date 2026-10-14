// Mounts routers and refuses to start when two handlers claim the same method and path,
// which has bitten us twice after merges.
import { logger } from '../logger.js';

export class RouteRegistry {
  /**
   * @param {import('express').Express} app
   */
  constructor(app) {
    this.app = app;
    /** @type {Map<string, string>} */
    this.seen = new Map();
  }

  /**
   * @param {string} prefix
   * @param {import('express').Router} router
   */
  mount(prefix, router) {
    for (const route of listRoutes(router)) {
      const signature = `${route.method} ${prefix}${route.path}/${route.handler.length}`;
      const key = `${route.method} ${prefix}${route.path}`;
      if (this.seen.has(key)) {
        throw new Error(`duplicate route ${key} (${this.seen.get(key)} and ${signature})`);
      }
      this.seen.set(key, signature);
    }
    this.app.use(prefix, router);
    logger.debug({ prefix, routes: this.seen.size }, 'mounted router');
  }
}

/**
 * @param {import('express').Router} router
 * @returns {{ method: string, path: string, handler: Function }[]}
 */
function listRoutes(router) {
  const out = [];
  for (const layer of router.stack ?? []) {
    /** @type {any} */
    const route = layer.route;
    if (!route) continue;
    for (const method of Object.keys(route.methods ?? {})) {
      const handlers = route.stack ?? [];
      out.push({ method: method.toUpperCase(), path: String(route.path), handler: handlers[handlers.length - 1]?.handle ?? (() => {}) });
    }
  }
  return out;
}
