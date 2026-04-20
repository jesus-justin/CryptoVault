import { NextFunction, Request, Response } from 'express';
import { ZodError } from 'zod';
import { ApiError, createApiResponse } from '../types/api.types';

/**
 * @description Global Express error handler that normalizes all failures to ApiResponse<null>.
 * @algorithm Error classification and response normalization
 * @reference Express error middleware pattern; Zod validation handling
 * @security Prevents stack trace leakage in production responses.
 * @param err Unknown error thrown from middleware/controllers/services.
 * @param req Express request.
 * @param res Express response.
 * @param next Express next function (unused; included for middleware signature compliance).
 * @returns JSON error response.
 */
export function errorHandler(
  err: unknown,
  req: Request,
  res: Response,
  next: NextFunction,
): Response {
  void req;
  void next;

  const requestId = res.locals.requestId as string | undefined;
  const resolvedRequestId = requestId ?? 'unknown';

  if (err instanceof ApiError) {
    return res.status(err.statusCode).json(
      createApiResponse<null>({
        success: false,
        data: null,
        error: err.message,
        requestId: resolvedRequestId,
      }),
    );
  }

  if (err instanceof ZodError) {
    const details = err.issues
      .map((issue) => `${issue.path.join('.') || 'body'}: ${issue.message}`)
      .join('; ');

    return res.status(400).json(
      createApiResponse<null>({
        success: false,
        data: null,
        error: `VALIDATION_ERROR: ${details}`,
        requestId: resolvedRequestId,
      }),
    );
  }

  const message = err instanceof Error ? err.message : 'Unknown error';
  console.error('Unhandled server error:', {
    requestId: resolvedRequestId,
    message,
    error: err,
  });

  return res.status(500).json(
    createApiResponse<null>({
      success: false,
      data: null,
      error: 'INTERNAL_SERVER_ERROR',
      requestId: resolvedRequestId,
    }),
  );
}
