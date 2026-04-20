import { NextFunction, Request, Response } from 'express';
import { hashingService } from '../services/hashing.service';
import { createApiResponse } from '../types/api.types';
import { AvalancheRequest, HashRequest, HmacRequest } from '../types/crypto.types';

function resolveRequestId(res: Response): string {
  const requestId = res.locals.requestId;
  return typeof requestId === 'string' ? requestId : 'unknown';
}

/**
 * @description Handles hash generation requests.
 * @algorithm SHA-2 | SHA-3 | MD5 (educational only)
 * @reference FIPS 180-4; FIPS 202
 * @security MD5 output includes explicit warning and must not be used for security decisions.
 * @param req Express request.
 * @param res Express response.
 * @param next Express next callback.
 * @returns Promise resolving to HTTP response.
 */
export async function hashData(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const body = req.body as HashRequest;
    const result = hashingService.hash(body.input, body.algorithm);

    res.locals.operation = 'HASH_GENERATE';
    res.locals.algorithm = body.algorithm;

    res.status(200).json(
      createApiResponse({
        success: true,
        data: result,
        error: null,
        requestId: resolveRequestId(res),
      }),
    );
  } catch (error: unknown) {
    next(error);
  }
}

/**
 * @description Handles HMAC generation requests.
 * @algorithm HMAC-SHA256 | HMAC-SHA512
 * @reference RFC 2104
 * @security Secret key material is never logged or echoed in responses.
 * @param req Express request.
 * @param res Express response.
 * @param next Express next callback.
 * @returns Promise resolving to HTTP response.
 */
export async function hmacData(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const body = req.body as HmacRequest;
    const result = hashingService.hmac(body.input, body.key, body.algorithm);

    res.locals.operation = 'HMAC_GENERATE';
    res.locals.algorithm = `HMAC-${body.algorithm.toUpperCase()}`;

    res.status(200).json(
      createApiResponse({
        success: true,
        data: result,
        error: null,
        requestId: resolveRequestId(res),
      }),
    );
  } catch (error: unknown) {
    next(error);
  }
}

/**
 * @description Handles avalanche-effect analysis requests.
 * @algorithm SHA-256 | SHA3-256
 * @reference Hash avalanche property demonstration
 * @security Educational diagnostic output only.
 * @param req Express request.
 * @param res Express response.
 * @param next Express next callback.
 * @returns Promise resolving to HTTP response.
 */
export async function hashAvalanche(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const body = req.body as AvalancheRequest;
    const result = hashingService.avalanche(body.input, body.algorithm);

    res.locals.operation = 'HASH_AVALANCHE';
    res.locals.algorithm = body.algorithm;

    res.status(200).json(
      createApiResponse({
        success: true,
        data: result,
        error: null,
        requestId: resolveRequestId(res),
      }),
    );
  } catch (error: unknown) {
    next(error);
  }
}
