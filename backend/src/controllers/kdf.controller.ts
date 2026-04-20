import { NextFunction, Request, Response } from 'express';
import { kdfService } from '../services/kdf.service';
import { createApiResponse } from '../types/api.types';
import { KdfDeriveRequest, KdfVerifyRequest } from '../types/crypto.types';

function resolveRequestId(res: Response): string {
  const requestId = res.locals.requestId;
  return typeof requestId === 'string' ? requestId : 'unknown';
}

/**
 * @description Handles KDF derive requests for bcrypt, Argon2id, PBKDF2, scrypt, and HKDF.
 * @algorithm bcrypt | argon2id | pbkdf2 | scrypt | hkdf
 * @reference RFC 9106; RFC 7914; RFC 5869; NIST SP 800-132
 * @security Passwords and key material are processed in service layer with secure defaults.
 * @param req Express request.
 * @param res Express response.
 * @param next Express next callback.
 * @returns Promise resolving to HTTP response.
 */
export async function deriveKdf(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const body = req.body as KdfDeriveRequest;

    const salt = typeof body.passphrase === 'string' && body.passphrase.length > 0
      ? Buffer.from(body.passphrase, 'utf8')
      : undefined;

    const inputKeyMaterial =
      typeof body.inputKeyMaterial === 'string' && body.inputKeyMaterial.length > 0
        ? Buffer.from(body.inputKeyMaterial, 'base64')
        : undefined;

    const result = await kdfService.derive(body.algorithm, {
      password: body.password,
      rounds: body.rounds,
      iterations: body.iterations,
      keyLength: body.keyLength,
      salt,
      info: body.info,
      inputKeyMaterial,
    });

    res.locals.operation = 'KDF_DERIVE';
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
 * @description Handles KDF verify requests for bcrypt and Argon2id.
 * @algorithm bcrypt | argon2id
 * @reference RFC 9106; bcrypt
 * @security Verification returns boolean only and avoids disclosing sensitive internals.
 * @param req Express request.
 * @param res Express response.
 * @param next Express next callback.
 * @returns Promise resolving to HTTP response.
 */
export async function verifyKdf(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const body = req.body as KdfVerifyRequest;
    const result = await kdfService.verify(body.algorithm, body.password, body.hash);

    res.locals.operation = 'KDF_VERIFY';
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
