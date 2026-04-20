import { randomBytes } from 'crypto';
import { ApiError } from '../types/api.types';

/**
 * @description Generates cryptographically secure random bytes for keys, IVs, nonces, and salts.
 * @algorithm CSPRNG (Node.js crypto.randomBytes)
 * @reference Node.js Crypto API - randomBytes
 * @security Never use Math.random() for cryptographic material; always use this wrapper.
 * @param length Number of bytes to generate.
 * @returns A Buffer containing cryptographically secure random bytes.
 */
export function secureBytes(length: number): Buffer {
  if (!Number.isInteger(length) || length <= 0) {
    throw new ApiError(400, 'INVALID_RANDOM_LENGTH', 'Random byte length must be a positive integer.');
  }

  return randomBytes(length);
}
