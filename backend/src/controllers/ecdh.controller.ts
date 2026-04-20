import { NextFunction, Request, Response } from 'express';
import { ecdhService } from '../services/ecdh.service';
import { createApiResponse } from '../types/api.types';
import { ECDHExchangeRequest } from '../types/crypto.types';

function resolveRequestId(res: Response): string {
  const requestId = res.locals.requestId;
  return typeof requestId === 'string' ? requestId : 'unknown';
}

/**
 * @description Generates X25519 key pair for ECDH exchange.
 * @algorithm X25519
 * @reference RFC 7748
 * @security Private key output must be handled securely by clients.
 * @param req Express request.
 * @param res Express response.
 * @param next Express next callback.
 * @returns Promise resolving to HTTP response.
 */
export async function generateEcdhKeyPair(_req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const result = ecdhService.generateKeyPair();

    res.locals.operation = 'ECDH_KEYGEN';
    res.locals.algorithm = 'X25519';

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
 * @description Computes X25519 shared secret and HKDF-derived key.
 * @algorithm X25519 + HKDF-SHA256
 * @reference RFC 7748; RFC 5869
 * @security Raw shared secret is returned for educational display only.
 * @param req Express request.
 * @param res Express response.
 * @param next Express next callback.
 * @returns Promise resolving to HTTP response.
 */
export async function exchangeEcdhSecret(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const body = req.body as Partial<ECDHExchangeRequest>;
    const result =
      body.myPrivateKey && body.theirPublicKey
        ? ecdhService.computeSharedSecret(body.myPrivateKey, body.theirPublicKey)
        : ecdhService.fullExchangeDemo();

    res.locals.operation = 'ECDH_EXCHANGE';
    res.locals.algorithm = 'X25519';

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
 * @description Runs a full Alice/Bob key exchange demonstration and returns both views.
 * @algorithm X25519 + HKDF-SHA256
 * @reference RFC 7748; RFC 5869
 * @security Educational demo endpoint; avoid exposing similar diagnostics in production environments.
 * @param req Express request.
 * @param res Express response.
 * @param next Express next callback.
 * @returns Promise resolving to HTTP response.
 */
export async function ecdhFullDemo(_req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const result = ecdhService.fullExchangeDemo();

    res.locals.operation = 'ECDH_FULL_DEMO';
    res.locals.algorithm = 'X25519';

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
