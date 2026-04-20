import { NextFunction, Request, Response } from 'express';
import { SignOptions } from 'jsonwebtoken';
import { env } from '../config/env';
import { jwtService } from '../services/jwt.service';
import { ApiError, createApiResponse } from '../types/api.types';
import { JwtAlgorithm } from '../types/crypto.types';

function resolveRequestId(res: Response): string {
  const requestId = res.locals.requestId;
  return typeof requestId === 'string' ? requestId : 'unknown';
}

/**
 * @description Signs a JWT using HS256, RS256, or ES256.
 * @algorithm HS256 | RS256 | ES256
 * @reference RFC 7519; RFC 7518
 * @security Signed token includes jti for revocation support.
 * @param req Express request.
 * @param res Express response.
 * @param next Express next callback.
 * @returns Promise resolving to HTTP response.
 */
export async function signJwt(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const body = req.body as {
      payload: Record<string, unknown>;
      algorithm: JwtAlgorithm;
      secretOrPrivateKey?: string;
      expiresIn?: string | number;
      issuer?: string;
      audience?: string | string[];
      subject?: string;
      notBefore?: string | number;
    };

    const resolvedSecretOrKey =
      body.secretOrPrivateKey ?? (body.algorithm === 'HS256' ? env.JWT_SECRET : undefined);

    if (!resolvedSecretOrKey) {
      throw new ApiError(400, 'MISSING_SIGNING_KEY', 'secretOrPrivateKey is required for non-HS256 algorithms.');
    }

    const signOptions: SignOptions = {};

    if (typeof body.expiresIn !== 'undefined') {
      signOptions.expiresIn = body.expiresIn as SignOptions['expiresIn'];
    }

    if (typeof body.issuer === 'string') {
      signOptions.issuer = body.issuer;
    }

    if (typeof body.audience !== 'undefined') {
      signOptions.audience = body.audience;
    }

    if (typeof body.subject === 'string') {
      signOptions.subject = body.subject;
    }

    if (typeof body.notBefore !== 'undefined') {
      signOptions.notBefore = body.notBefore as SignOptions['notBefore'];
    }

    const token = await jwtService.sign(body.payload, body.algorithm, resolvedSecretOrKey, signOptions);

    res.locals.operation = 'JWT_SIGN';
    res.locals.algorithm = body.algorithm;

    res.status(200).json(
      createApiResponse({
        success: true,
        data: { token, algorithm: body.algorithm },
        error: null,
        requestId: resolveRequestId(res),
      }),
    );
  } catch (error: unknown) {
    next(error);
  }
}

/**
 * @description Verifies JWT validity and revocation status.
 * @algorithm HS256 | RS256 | ES256
 * @reference RFC 7519; RFC 7518
 * @security Token revocation is checked via jti before returning valid=true.
 * @param req Express request.
 * @param res Express response.
 * @param next Express next callback.
 * @returns Promise resolving to HTTP response.
 */
export async function verifyJwt(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const body = req.body as {
      token: string;
      algorithm: JwtAlgorithm;
      secretOrPublicKey: string;
    };

    const result = await jwtService.verify(body.token, body.algorithm, body.secretOrPublicKey);

    res.locals.operation = 'JWT_VERIFY';
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
 * @description Decodes a JWT without verification for inspection tooling.
 * @algorithm JWT decode
 * @reference RFC 7519
 * @security Decode output is informational only and not trusted by default.
 * @param req Express request.
 * @param res Express response.
 * @param next Express next callback.
 * @returns Promise resolving to HTTP response.
 */
export async function decodeJwt(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const body = req.body as { token: string };
    const result = jwtService.decode(body.token);

    res.locals.operation = 'JWT_DECODE';
    res.locals.algorithm = 'JWT';

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
 * @description Creates a compact JWE token using RSA-OAEP-256 and A256GCM.
 * @algorithm RSA-OAEP-256 + A256GCM
 * @reference RFC 7516
 * @security Payload confidentiality depends on recipient public key trust.
 * @param req Express request.
 * @param res Express response.
 * @param next Express next callback.
 * @returns Promise resolving to HTTP response.
 */
export async function createJwe(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const body = req.body as {
      payload: Record<string, unknown>;
      publicKey: string;
    };

    const token = await jwtService.createJWE(body.payload, body.publicKey);

    res.locals.operation = 'JWT_CREATE_JWE';
    res.locals.algorithm = 'RSA-OAEP-256+A256GCM';

    res.status(200).json(
      createApiResponse({
        success: true,
        data: {
          token,
          algorithm: 'RSA-OAEP-256',
          encryption: 'A256GCM',
        },
        error: null,
        requestId: resolveRequestId(res),
      }),
    );
  } catch (error: unknown) {
    next(error);
  }
}

/**
 * @description Revokes a JWT by storing its jti until expiration.
 * @algorithm Revocation list tracking
 * @reference Internal CryptoVault JWT revocation policy
 * @security Revoked tokens are denied in verify flow even if signature remains valid.
 * @param req Express request.
 * @param res Express response.
 * @param next Express next callback.
 * @returns Promise resolving to HTTP response.
 */
export async function revokeJwt(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const body = req.body as {
      jti: string;
      expiresAt: number;
    };

    jwtService.revokeToken(body.jti, body.expiresAt);

    res.locals.operation = 'JWT_REVOKE';
    res.locals.algorithm = 'JWT';

    res.status(200).json(
      createApiResponse({
        success: true,
        data: { revoked: true, jti: body.jti },
        error: null,
        requestId: resolveRequestId(res),
      }),
    );
  } catch (error: unknown) {
    next(error);
  }
}
