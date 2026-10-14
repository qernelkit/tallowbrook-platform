import { logger } from '../logger.js';

export class HttpError extends Error {
  /**
   * @param {number} status
   * @param {string} code
   * @param {string} [message]
   * @param {Record<string, unknown>} [details]
   */
  constructor(status, code, message, details) {
    super(message ?? code);
    this.status = status;
    this.code = code;
    this.details = details;
  }
}

export const badRequest = (code, details) => new HttpError(400, code, 'request is not valid', details);
export const unauthorized = (code = 'unauthorized') => new HttpError(401, code);
export const forbidden = (code = 'forbidden') => new HttpError(403, code);
export const notFoundError = (what) => new HttpError(404, 'not_found', `${what} not found`);
export const conflict = (code) => new HttpError(409, code);

/**
 * @param {import('express').Request} req
 * @param {import('express').Response} res
 */
export function notFound(req, res) {
  res.status(404).json({ error: 'not_found', path: req.path });
}

/**
 * @param {any} err
 * @param {import('express').Request} req
 * @param {import('express').Response} res
 * @param {import('express').NextFunction} next
 */
export function errorHandler(err, req, res, next) {
  if (res.headersSent) {
    next(err);
    return;
  }
  if (err instanceof HttpError) {
    res.status(err.status).json({ error: err.code, message: err.message, details: err.details });
    return;
  }
  logger.error({ err, requestId: res.locals.requestId, path: req.path }, 'unhandled error');
  res.status(500).json({ error: 'internal', requestId: res.locals.requestId });
}

/**
 * Wraps an async handler so a rejected promise reaches the error handler.
 * @param {(req: import('express').Request<Record<string, string>>, res: import('express').Response) => Promise<unknown>} fn
 * @returns {import('express').RequestHandler}
 */
export const asyncHandler = (fn) => (req, res, next) => {
  fn(/** @type {any} */ (req), res).catch(next);
};
