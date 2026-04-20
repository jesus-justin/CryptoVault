import { randomUUID } from 'crypto';
import { NextFunction, Request, Response } from 'express';

/**
 * @description Attaches a request ID to the request lifecycle and response headers.
 * @algorithm UUID v4 request correlation
 * @reference Internal CryptoVault tracing policy
 * @security Reuses client-supplied X-Request-ID when provided; otherwise generates a new UUID.
 * @param req Express request.
 * @param res Express response.
 * @param next Express next middleware callback.
 * @returns Void.
 */
export function requestIdMiddleware(req: Request, res: Response, next: NextFunction): void {
  const incomingRequestIdHeader = req.header('X-Request-ID');
  const requestId = incomingRequestIdHeader && incomingRequestIdHeader.trim() ? incomingRequestIdHeader : randomUUID();

  res.locals.requestId = requestId;
  res.setHeader('X-Request-ID', requestId);

  next();
}
