import { NextFunction, Request, Response } from 'express';
import { ZodTypeAny } from 'zod';
import { ApiError } from '../types/api.types';

/**
 * @description Creates request body validation middleware using a Zod schema.
 * @algorithm Zod schema validation
 * @reference Zod safeParse API
 * @security Rejects invalid input before controller logic executes.
 * @param schema Zod schema used to validate req.body.
 * @returns Express middleware that validates and normalizes req.body.
 */
export function validateBody(schema: ZodTypeAny) {
  return (req: Request, _res: Response, next: NextFunction): void => {
    const parsed = schema.safeParse(req.body);

    if (!parsed.success) {
      throw new ApiError(400, 'VALIDATION_ERROR', 'Request body validation failed.', parsed.error.issues);
    }

    req.body = parsed.data;
    next();
  };
}
