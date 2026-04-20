import { Router } from 'express';
import { createApiResponse } from '../types/api.types';
import { getAlgorithmMetadata } from '../utils/algorithmMetadata';

const healthRouter = Router();

healthRouter.get('/health', (_req, res) => {
  const requestId = typeof res.locals.requestId === 'string' ? res.locals.requestId : 'unknown';

  res.status(200).json(
    createApiResponse({
      success: true,
      data: {
        status: 'ok',
        version: '2.0.0',
        uptime: process.uptime(),
      },
      error: null,
      requestId,
    }),
  );
});

healthRouter.get('/algorithms', (_req, res) => {
  const requestId = typeof res.locals.requestId === 'string' ? res.locals.requestId : 'unknown';

  res.status(200).json(
    createApiResponse({
      success: true,
      data: getAlgorithmMetadata(),
      error: null,
      requestId,
    }),
  );
});

export default healthRouter;
