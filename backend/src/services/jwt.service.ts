import { createPrivateKey, createPublicKey, KeyObject, randomUUID } from 'crypto';
import jwt, {
  JsonWebTokenError,
  JwtPayload,
  NotBeforeError,
  SignOptions,
  TokenExpiredError,
} from 'jsonwebtoken';
import {
  CompactEncrypt,
  SignJWT,
  errors as joseErrors,
  importSPKI,
  jwtVerify,
  JWTHeaderParameters,
  KeyLike,
  ProtectedHeaderParameters,
} from 'jose';
import { ApiError } from '../types/api.types';
import { DecodedToken, JwtAlgorithm, VerifyResult } from '../types/crypto.types';

const REVOCATION_CLEANUP_INTERVAL_MS = 10 * 60 * 1000;

class JwtService {
  private readonly revokedTokens = new Map<string, number>();

  constructor() {
    const cleanupTimer = setInterval(() => {
      this.cleanupRevokedTokens();
    }, REVOCATION_CLEANUP_INTERVAL_MS);

    cleanupTimer.unref();
  }

  /**
   * @description Signs a JWT with HS256, RS256, or ES256 and always attaches a jti claim.
   * @algorithm HS256 | RS256 | ES256
   * @reference RFC 7519; RFC 7518
   * @security Always includes jti for revocation checks and sets typ=JWT for JOSE-based signatures.
   * @param payload JWT payload object.
   * @param algorithm JWT algorithm.
   * @param secret Signing secret (HS256) or private key (RS256/ES256).
   * @param options Optional JWT signing options.
   * @returns Signed JWT string.
   */
  async sign(
    payload: Record<string, unknown>,
    algorithm: JwtAlgorithm,
    secret: string | KeyObject,
    options: SignOptions = {},
  ): Promise<string> {
    const jti = randomUUID();

    if (algorithm === 'HS256') {
      const hsSecret = this.requireStringSecret(secret, 'HS256 signing requires a string secret.');

      try {
        return jwt.sign(payload, hsSecret, {
          ...options,
          algorithm: 'HS256',
          jwtid: jti,
        });
      } catch (error: unknown) {
        throw new ApiError(400, 'JWT_SIGN_FAILED', 'Failed to sign HS256 token.', error);
      }
    }

    const privateKey = this.resolvePrivateKey(secret);

    try {
      const josePayload = this.toJosePayload(payload);
      const signer = new SignJWT(josePayload)
        .setProtectedHeader(this.toProtectedHeader(algorithm))
        .setJti(jti)
        .setIssuedAt();

      if (typeof options.expiresIn !== 'undefined') {
        signer.setExpirationTime(options.expiresIn);
      }

      if (typeof options.notBefore !== 'undefined') {
        signer.setNotBefore(options.notBefore);
      }

      if (typeof options.issuer === 'string') {
        signer.setIssuer(options.issuer);
      }

      if (typeof options.subject === 'string') {
        signer.setSubject(options.subject);
      }

      if (typeof options.audience === 'string' || Array.isArray(options.audience)) {
        signer.setAudience(options.audience);
      }

      return await signer.sign(privateKey);
    } catch (error: unknown) {
      throw new ApiError(400, 'JWT_SIGN_FAILED', `Failed to sign ${algorithm} token.`, error);
    }
  }

  /**
   * @description Verifies JWT signature/claims and checks token revocation via jti.
   * @algorithm HS256 | RS256 | ES256
   * @reference RFC 7519; RFC 7518
   * @security Revoked tokens are rejected even if signature is valid.
   * @param token JWT string.
   * @param algorithm Expected JWT algorithm.
   * @param secret Verification secret (HS256) or public key (RS256/ES256).
   * @returns Verification result with validity and normalized error shape.
   */
  async verify(token: string, algorithm: JwtAlgorithm, secret: string | KeyObject): Promise<VerifyResult> {
    try {
      if (algorithm === 'HS256') {
        const hsSecret = this.requireStringSecret(secret, 'HS256 verification requires a string secret.');
        const verified = jwt.verify(token, hsSecret, { algorithms: ['HS256'] });
        const normalizedPayload = this.normalizePayload(verified);
        const jti = this.extractJti(normalizedPayload);

        if (jti && this.isRevoked(jti)) {
          return {
            valid: false,
            error: 'TOKEN_REVOKED',
            jti,
          };
        }

        return {
          valid: true,
          payload: normalizedPayload,
          jti,
        };
      }

      const publicKey = this.resolvePublicKey(secret);
      const { payload, protectedHeader } = await jwtVerify(token, publicKey, { algorithms: [algorithm] });
      const normalizedPayload = this.normalizeJosePayload(payload);
      const jti = this.extractJti(normalizedPayload);

      if (jti && this.isRevoked(jti)) {
        return {
          valid: false,
          error: 'TOKEN_REVOKED',
          jti,
        };
      }

      return {
        valid: true,
        payload: normalizedPayload,
        header: this.normalizeJoseHeader(protectedHeader),
        jti,
      };
    } catch (error: unknown) {
      if (error instanceof TokenExpiredError) {
        return {
          valid: false,
          error: 'TOKEN_EXPIRED',
          expiredAt: error.expiredAt.toISOString(),
          message: error.message,
        };
      }

      if (error instanceof NotBeforeError) {
        return {
          valid: false,
          error: 'TOKEN_NOT_ACTIVE',
          message: error.message,
        };
      }

      if (error instanceof JsonWebTokenError) {
        return {
          valid: false,
          error: 'INVALID_TOKEN',
          message: error.message,
        };
      }

      if (error instanceof joseErrors.JWTExpired) {
        return {
          valid: false,
          error: 'TOKEN_EXPIRED',
          message: error.message,
        };
      }

      if (error instanceof joseErrors.JWTClaimValidationFailed && error.claim === 'nbf') {
        return {
          valid: false,
          error: 'TOKEN_NOT_ACTIVE',
          message: error.message,
        };
      }

      return {
        valid: false,
        error: 'INVALID_TOKEN',
        message: error instanceof Error ? error.message : 'Token verification failed.',
      };
    }
  }

  /**
   * @description Decodes JWT without signature verification and provides structured token parts.
   * @algorithm JWT decode (non-verifying)
   * @reference RFC 7519
   * @security Output is informational only; decoded content must not be treated as trusted.
   * @param token JWT string.
   * @returns Header, payload, signature segment, and expiration hint.
   */
  decode(token: string): DecodedToken {
    const parts = token.split('.');
    const decoded = jwt.decode(token, { complete: true });

    if (!decoded || typeof decoded !== 'object') {
      return {
        header: null,
        payload: null,
        signature: parts.length === 3 ? parts[2] : null,
        isExpired: false,
      };
    }

    const complete = decoded as { header: JwtPayload | Record<string, unknown>; payload: JwtPayload | string };
    const payload =
      typeof complete.payload === 'string' ? { value: complete.payload } : this.normalizePayload(complete.payload);
    const exp = this.readNumericExp(payload);

    return {
      header: this.normalizePayload(complete.header),
      payload,
      signature: parts.length === 3 ? parts[2] : null,
      isExpired: typeof exp === 'number' ? exp * 1000 < Date.now() : false,
    };
  }

  /**
   * @description Creates a compact JWE using RSA-OAEP-256 key management and A256GCM content encryption.
   * @algorithm RSA-OAEP-256 + A256GCM
   * @reference RFC 7516
   * @security Encrypts payload for confidentiality; caller must use trusted recipient public key.
   * @param payload Object payload to encrypt.
   * @param publicKeyPem Recipient RSA public key in PEM format.
   * @returns Compact serialized JWE string.
   */
  async createJWE(payload: Record<string, unknown>, publicKeyPem: string): Promise<string> {
    try {
      const publicKey = await importSPKI(publicKeyPem, 'RSA-OAEP-256');
      const plaintext = Buffer.from(JSON.stringify(payload), 'utf8');

      return await new CompactEncrypt(plaintext)
        .setProtectedHeader({ alg: 'RSA-OAEP-256', enc: 'A256GCM' })
        .encrypt(publicKey);
    } catch (error: unknown) {
      throw new ApiError(400, 'JWE_CREATE_FAILED', 'Failed to create JWE token.', error);
    }
  }

  /**
   * @description Adds a token jti to the revocation map until its expiration time.
   * @algorithm Revocation list tracking
   * @reference Internal CryptoVault token revocation policy
   * @security Expired revocation entries are cleaned periodically.
   * @param jti Token identifier.
   * @param expiresAt Expiration timestamp in milliseconds.
   * @returns Void.
   */
  revokeToken(jti: string, expiresAt: number): void {
    if (!jti) {
      throw new ApiError(400, 'INVALID_JTI', 'jti is required for token revocation.');
    }

    if (!Number.isFinite(expiresAt) || expiresAt <= Date.now()) {
      throw new ApiError(400, 'INVALID_EXPIRY', 'expiresAt must be a future UNIX timestamp in milliseconds.');
    }

    this.revokedTokens.set(jti, expiresAt);
  }

  /**
   * @description Checks whether a token jti is revoked and prunes expired revocation entries.
   * @algorithm Revocation list lookup
   * @reference Internal CryptoVault token revocation policy
   * @security Automatically removes stale revocation records to control memory usage.
   * @param jti Token identifier.
   * @returns True when token identifier is currently revoked.
   */
  isRevoked(jti: string): boolean {
    this.cleanupRevokedTokens();

    const expiresAt = this.revokedTokens.get(jti);
    if (!expiresAt) {
      return false;
    }

    if (expiresAt <= Date.now()) {
      this.revokedTokens.delete(jti);
      return false;
    }

    return true;
  }

  private cleanupRevokedTokens(): void {
    const now = Date.now();

    for (const [jti, expiresAt] of this.revokedTokens.entries()) {
      if (expiresAt <= now) {
        this.revokedTokens.delete(jti);
      }
    }
  }

  private requireStringSecret(secret: string | KeyObject, message: string): string {
    if (typeof secret !== 'string') {
      throw new ApiError(400, 'INVALID_SECRET_TYPE', message);
    }

    return secret;
  }

  private resolvePrivateKey(secret: string | KeyObject): KeyLike {
    if (secret instanceof KeyObject) {
      return secret;
    }

    return createPrivateKey(secret);
  }

  private resolvePublicKey(secret: string | KeyObject): KeyLike {
    if (secret instanceof KeyObject) {
      return secret;
    }

    return createPublicKey(secret);
  }

  private toProtectedHeader(algorithm: 'RS256' | 'ES256'): JWTHeaderParameters {
    return {
      alg: algorithm,
      typ: 'JWT',
    };
  }

  private toJosePayload(payload: Record<string, unknown>): JwtPayload {
    const normalized: JwtPayload = {};

    for (const [key, value] of Object.entries(payload)) {
      if (typeof value !== 'undefined') {
        normalized[key] = value;
      }
    }

    return normalized;
  }

  private normalizePayload(payload: JwtPayload | string | Record<string, unknown>): Record<string, unknown> {
    if (typeof payload === 'string') {
      return { value: payload };
    }

    const normalized: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(payload)) {
      normalized[key] = value;
    }

    return normalized;
  }

  private normalizeJosePayload(payload: JwtPayload): Record<string, unknown> {
    const normalized: Record<string, unknown> = {};

    for (const [key, value] of Object.entries(payload)) {
      normalized[key] = value;
    }

    return normalized;
  }

  private normalizeJoseHeader(header: ProtectedHeaderParameters): Record<string, unknown> {
    const normalized: Record<string, unknown> = {};

    for (const [key, value] of Object.entries(header)) {
      normalized[key] = value;
    }

    return normalized;
  }

  private extractJti(payload: Record<string, unknown> | undefined): string | undefined {
    if (!payload) {
      return undefined;
    }

    const value = payload.jti;
    return typeof value === 'string' ? value : undefined;
  }

  private readNumericExp(payload: Record<string, unknown>): number | undefined {
    const exp = payload.exp;
    return typeof exp === 'number' ? exp : undefined;
  }
}

export const jwtService = new JwtService();
