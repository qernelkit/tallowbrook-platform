import { randomUUID } from 'node:crypto';

const HEADER = 'x-request-id';
const VALID = /^[A-Za-z0-9-]{8,64}$/;

/**
 * Accepts a caller's request id when it looks sane, otherwise mints one, and echoes
 * it back so support can find the request in the logs.
 * @param {import('express').Request} req
 * @param {import('express').Response} res
 * @param {import('express').NextFunction} next
 */
export function requestId(req, res, next) {
  const incoming = req.get(HEADER);
  const id = incoming && VALID.test(incoming) ? incoming : randomUUID();
  res.locals.requestId = id;
  res.setHeader(HEADER, id);
  next();
}
