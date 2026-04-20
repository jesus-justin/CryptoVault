import cookieParser from 'cookie-parser';
import cors from 'cors';
import csrf from 'csurf';
import express, { NextFunction, Request, Response } from 'express';
import rateLimit from 'express-rate-limit';
import morgan from 'morgan';
import { env } from './config/env';
import { setupSwagger } from './docs/swagger';
import { auditLoggerMiddleware } from './middleware/auditLogger';
import { errorHandler } from './middleware/errorHandler';
import { requestIdMiddleware } from './middleware/requestId';
import { securityHeadersMiddleware } from './middleware/securityHeaders';
import apiV1Router from './routes';
import { createApiResponse } from './types/api.types';

export const app = express();

const allowedOriginSet = new Set(env.ALLOWED_ORIGINS);

app.disable('x-powered-by');
app.use(requestIdMiddleware);
app.use(morgan('combined'));
app.use(securityHeadersMiddleware);
app.use(cookieParser());
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: false, limit: '1mb' }));

app.use(
  cors({
    origin(origin, callback) {
      if (!origin || allowedOriginSet.has(origin)) {
        callback(null, true);
        return;
      }

      callback(new Error('Origin not allowed by CORS policy'));
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Request-ID', 'X-CSRF-Token'],
    exposedHeaders: ['X-Request-ID', 'Retry-After'],
  }),
);

const csrfProtection = csrf({
  cookie: {
    httpOnly: true,
    secure: env.NODE_ENV === 'production',
    sameSite: 'strict',
  },
});

app.use((req: Request, res: Response, next: NextFunction) => {
  if (env.NODE_ENV !== 'production') {
    next();
    return;
  }

  if (req.method === 'GET' || req.method === 'HEAD' || req.method === 'OPTIONS') {
    next();
    return;
  }

  csrfProtection(req, res, next);
});

const kdfRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: 'Too many KDF requests, please retry later.',
});

const asymmetricRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: 'Too many asymmetric cryptography requests, please retry later.',
});

const defaultRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: 'Too many requests, please retry later.',
});

app.use('/api/v1/kdf', kdfRateLimiter);
app.use('/api/v1/asymmetric', asymmetricRateLimiter);
app.use('/api/v1', defaultRateLimiter);

setupSwagger(app);

app.use(auditLoggerMiddleware);
app.use('/api/v1', apiV1Router);

app.use('/api', (_req: Request, res: Response) => {
  const requestId = typeof res.locals.requestId === 'string' ? res.locals.requestId : 'unknown';

  res.status(404).json(
    createApiResponse<null>({
      success: false,
      data: null,
      error: 'Use /api/v1/* endpoints.',
      requestId,
    }),
  );
});

app.use((_req: Request, res: Response) => {
  const requestId = typeof res.locals.requestId === 'string' ? res.locals.requestId : 'unknown';

  res.status(404).json(
    createApiResponse<null>({
      success: false,
      data: null,
      error: 'Route not found.',
      requestId,
    }),
  );
});

app.use(errorHandler);

if (env.NODE_ENV !== 'test') {
  app.listen(env.PORT, () => {
    console.log(`CryptoVault API server running on port ${env.PORT}`);
    console.log('Swagger docs available at /api/v1/docs');
  });
}

export default app;
