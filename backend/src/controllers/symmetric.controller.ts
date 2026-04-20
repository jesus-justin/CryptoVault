import { NextFunction, Request, Response } from 'express';
import { createApiResponse } from '../types/api.types';
import { SymmetricDecryptRequest, SymmetricEncryptRequest } from '../types/crypto.types';
import { symmetricService } from '../services/symmetric.service';

function resolveRequestId(res: Response): string {
  const requestId = res.locals.requestId;
  return typeof requestId === 'string' ? requestId : 'unknown';
}

/**
 * @description Handles symmetric encryption requests and returns standardized API response payload.
 * @algorithm AES-256-GCM | ChaCha20-Poly1305 | AES-256-CBC
 * @reference NIST SP 800-38D; RFC 8439; NIST SP 800-38A
 * @security Derives key material from passphrase and never returns raw key bytes.
 * @param req Express request.
 * @param res Express response.
 * @param next Express next callback.
 * @returns Promise resolving to HTTP response.
 */
export async function encryptSymmetric(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const body = req.body as SymmetricEncryptRequest;
    const key = symmetricService.deriveKeyFromPassphrase(body.passphrase);

    try {
      const result = symmetricService.encrypt(body.plaintext, key, body.algorithm);
      res.locals.operation = 'SYMMETRIC_ENCRYPT';
      res.locals.algorithm = body.algorithm;

      res.status(200).json(
        createApiResponse({
          success: true,
          data: result,
          error: null,
          requestId: resolveRequestId(res),
        }),
      );
    } finally {
      key.fill(0);
    }
  } catch (error: unknown) {
    next(error);
  }
}

/**
 * @description Handles symmetric decryption requests and returns standardized API response payload.
 * @algorithm AES-256-GCM | ChaCha20-Poly1305 | AES-256-CBC
 * @reference NIST SP 800-38D; RFC 8439; NIST SP 800-38A
 * @security Requires authTag for AEAD modes and never logs sensitive request data.
 * @param req Express request.
 * @param res Express response.
 * @param next Express next callback.
 * @returns Promise resolving to HTTP response.
 */
export async function decryptSymmetric(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const body = req.body as SymmetricDecryptRequest;
    const key = symmetricService.deriveKeyFromPassphrase(body.passphrase);

    try {
      const ivOrNonce = body.algorithm === 'ChaCha20-Poly1305' ? body.nonce ?? '' : body.iv ?? '';
      const result = symmetricService.decrypt(body.ciphertext, key, body.algorithm, ivOrNonce, body.authTag);

      res.locals.operation = 'SYMMETRIC_DECRYPT';
      res.locals.algorithm = body.algorithm;

      res.status(200).json(
        createApiResponse({
          success: true,
          data: result,
          error: null,
          requestId: resolveRequestId(res),
        }),
      );
    } finally {
      key.fill(0);
    }
  } catch (error: unknown) {
    next(error);
  }
}
