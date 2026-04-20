import { NextFunction, Request, Response } from 'express';
import helmet from 'helmet';

const helmetMiddleware = helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", 'data:'],
      connectSrc: ["'self'"],
      frameSrc: ["'none'"],
      objectSrc: ["'none'"],
    },
  },
  hsts: {
    maxAge: 63_072_000,
    includeSubDomains: true,
    preload: true,
  },
  noSniff: true,
  frameguard: { action: 'deny' },
});

/**
 * @description Applies hardened HTTP security headers using Helmet and custom hardening headers.
 * @algorithm HTTP response header hardening
 * @reference Helmet.js documentation; OWASP secure headers guidance
 * @security Enforces CSP, HSTS, frame denial, MIME sniff prevention, and XSS filter compatibility header.
 * @param req Express request.
 * @param res Express response.
 * @param next Express next middleware callback.
 * @returns Void.
 */
export function securityHeadersMiddleware(req: Request, res: Response, next: NextFunction): void {
  helmetMiddleware(req, res, (helmetError?: unknown) => {
    if (helmetError) {
      next(helmetError);
      return;
    }

    res.setHeader('X-XSS-Protection', '1; mode=block');
    next();
  });
}
