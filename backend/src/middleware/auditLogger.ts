import { NextFunction, Request, Response } from 'express';
import { createLogger, format, transports } from 'winston';

const auditLogger = createLogger({
  level: 'info',
  format: format.combine(format.timestamp(), format.json()),
  transports: [new transports.Console()],
});

/**
 * @description Logs structured crypto operation audit events after response completion.
 * @algorithm Request lifecycle duration logging
 * @reference Internal CryptoVault audit policy
 * @security Never logs request body, plaintext, keys, passwords, or tokens.
 * @param req Express request.
 * @param res Express response.
 * @param next Express next middleware callback.
 * @returns Void.
 */
export function auditLoggerMiddleware(req: Request, res: Response, next: NextFunction): void {
  const startNs = process.hrtime.bigint();

  res.on('finish', () => {
    const endNs = process.hrtime.bigint();
    const durationMs = Number(endNs - startNs) / 1_000_000;

    const operation = typeof res.locals.operation === 'string' ? res.locals.operation : 'UNKNOWN_OPERATION';
    const algorithm = typeof res.locals.algorithm === 'string' ? res.locals.algorithm : 'UNKNOWN_ALGORITHM';
    const requestId = typeof res.locals.requestId === 'string' ? res.locals.requestId : 'unknown';

    auditLogger.info({
      level: 'info',
      event: 'CRYPTO_OPERATION',
      operation,
      algorithm,
      duration_ms: Number(durationMs.toFixed(3)),
      statusCode: res.statusCode,
      ip: req.ip,
      requestId,
      timestamp: new Date().toISOString(),
    });
  });

  next();
}
