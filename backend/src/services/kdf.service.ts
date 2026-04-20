import { hkdfSync, pbkdf2Sync, scrypt as scryptCallback } from 'crypto';
import argon2 from 'argon2';
import bcrypt from 'bcryptjs';
import { ApiError } from '../types/api.types';
import {
  Argon2Result,
  BcryptResult,
  HkdfResult,
  KdfAlgorithm,
  KdfDeriveResult,
  KdfVerifyResult,
  Pbkdf2Result,
  ScryptResult,
} from '../types/crypto.types';
import { secureBytes } from '../utils/secureBytes';
import { zeroBuffer, zeroBufferIfPresent } from '../utils/zeroBuffer';

const DEFAULT_BCRYPT_ROUNDS = 12;
const DEFAULT_PBKDF2_ITERATIONS = 600_000;
const DEFAULT_DERIVED_KEY_LENGTH = 32;
const DEFAULT_SALT_LENGTH = 32;

const ARGON2_MEMORY_COST = 65_536;
const ARGON2_TIME_COST = 3;
const ARGON2_PARALLELISM = 4;

const SCRYPT_N = 131_072;
const SCRYPT_R = 8;
const SCRYPT_P = 1;

class KdfService {
  /**
   * @description Hashes a password using bcrypt with configurable rounds.
   * @algorithm bcrypt
   * @reference Provos and Mazieres (USENIX 1999)
   * @security Use at least 12 rounds in production.
   * @param password Plaintext password.
   * @param rounds Cost factor for bcrypt.
   * @returns bcrypt hash and metadata.
   */
  async bcryptHash(password: string, rounds = DEFAULT_BCRYPT_ROUNDS): Promise<BcryptResult> {
    if (!password) {
      throw new ApiError(400, 'INVALID_PASSWORD', 'Password is required for bcrypt hashing.');
    }

    if (!Number.isInteger(rounds) || rounds < 10 || rounds > 16) {
      throw new ApiError(400, 'INVALID_BCRYPT_ROUNDS', 'bcrypt rounds must be an integer between 10 and 16.');
    }

    try {
      const hash = await bcrypt.hash(password, rounds);
      return {
        hash,
        algorithm: 'bcrypt',
        rounds,
      };
    } catch (error: unknown) {
      throw new ApiError(500, 'BCRYPT_HASH_FAILED', 'Failed to hash password with bcrypt.', error);
    }
  }

  /**
   * @description Verifies a password against a bcrypt hash.
   * @algorithm bcrypt
   * @reference Provos and Mazieres (USENIX 1999)
   * @security Compare operation is handled by bcrypt implementation.
   * @param password Candidate plaintext password.
   * @param hash Existing bcrypt hash.
   * @returns True if password matches hash.
   */
  async bcryptVerify(password: string, hash: string): Promise<boolean> {
    if (!password || !hash) {
      throw new ApiError(400, 'INVALID_BCRYPT_VERIFY_INPUT', 'Password and hash are required for bcrypt verify.');
    }

    try {
      return await bcrypt.compare(password, hash);
    } catch (error: unknown) {
      throw new ApiError(400, 'BCRYPT_VERIFY_FAILED', 'Failed to verify bcrypt hash.', error);
    }
  }

  /**
   * @description Hashes a password using Argon2id with secure memory-hard defaults.
   * @algorithm Argon2id
   * @reference RFC 9106
   * @security Memory-hard settings increase resistance to GPU/ASIC cracking.
   * @param password Plaintext password.
   * @returns Argon2 hash and parameter metadata.
   */
  async argon2Hash(password: string): Promise<Argon2Result> {
    if (!password) {
      throw new ApiError(400, 'INVALID_PASSWORD', 'Password is required for Argon2id hashing.');
    }

    try {
      const hash = await argon2.hash(password, {
        type: argon2.argon2id,
        memoryCost: ARGON2_MEMORY_COST,
        timeCost: ARGON2_TIME_COST,
        parallelism: ARGON2_PARALLELISM,
      });

      return {
        hash,
        algorithm: 'argon2id',
        memoryCost: ARGON2_MEMORY_COST,
        timeCost: ARGON2_TIME_COST,
        parallelism: ARGON2_PARALLELISM,
      };
    } catch (error: unknown) {
      throw new ApiError(500, 'ARGON2_HASH_FAILED', 'Failed to hash password with Argon2id.', error);
    }
  }

  /**
   * @description Verifies a password against an Argon2id hash.
   * @algorithm Argon2id
   * @reference RFC 9106
   * @security Verification is delegated to Argon2 implementation.
   * @param password Candidate plaintext password.
   * @param hash Existing Argon2 hash.
   * @returns True if password matches hash.
   */
  async argon2Verify(password: string, hash: string): Promise<boolean> {
    if (!password || !hash) {
      throw new ApiError(400, 'INVALID_ARGON2_VERIFY_INPUT', 'Password and hash are required for Argon2 verify.');
    }

    try {
      return await argon2.verify(hash, password);
    } catch (error: unknown) {
      throw new ApiError(400, 'ARGON2_VERIFY_FAILED', 'Failed to verify Argon2 hash.', error);
    }
  }

  /**
   * @description Derives a symmetric key from password and salt using PBKDF2-SHA256.
   * @algorithm PBKDF2-SHA256
   * @reference NIST SP 800-132
   * @security Uses high iteration count; salt should be unique and random per password.
   * @param password Password input for key derivation.
   * @param salt Optional salt. When omitted, a 32-byte secure random salt is generated.
   * @param iterations Iteration count (default 600000).
   * @param keyLength Output key length in bytes.
   * @returns Base64 key, base64 salt, and parameters.
   */
  pbkdf2Derive(
    password: string,
    salt?: Buffer,
    iterations = DEFAULT_PBKDF2_ITERATIONS,
    keyLength = DEFAULT_DERIVED_KEY_LENGTH,
  ): Pbkdf2Result {
    if (!password) {
      throw new ApiError(400, 'INVALID_PASSWORD', 'Password is required for PBKDF2 derivation.');
    }

    if (!Number.isInteger(iterations) || iterations < 100_000) {
      throw new ApiError(400, 'INVALID_PBKDF2_ITERATIONS', 'PBKDF2 iterations must be an integer >= 100000.');
    }

    if (!Number.isInteger(keyLength) || keyLength < 16 || keyLength > 64) {
      throw new ApiError(400, 'INVALID_KEY_LENGTH', 'PBKDF2 key length must be an integer between 16 and 64 bytes.');
    }

    const workingSalt = salt ? Buffer.from(salt) : secureBytes(DEFAULT_SALT_LENGTH);
    let derivedKey: Buffer | undefined;

    try {
      derivedKey = pbkdf2Sync(password, workingSalt, iterations, keyLength, 'sha256');

      return {
        key: derivedKey.toString('base64'),
        salt: workingSalt.toString('base64'),
        iterations,
        algorithm: 'PBKDF2-SHA256',
      };
    } catch (error: unknown) {
      throw new ApiError(500, 'PBKDF2_DERIVE_FAILED', 'Failed to derive key using PBKDF2-SHA256.', error);
    } finally {
      zeroBuffer(workingSalt);
      zeroBufferIfPresent(derivedKey);
    }
  }

  /**
   * @description Derives a key using scrypt with memory-hard parameters.
   * @algorithm scrypt
   * @reference RFC 7914
   * @security Uses N=131072, r=8, p=1 as recommended profile.
   * @param password Password input for key derivation.
   * @param salt Optional salt. When omitted, a 32-byte secure random salt is generated.
   * @returns Base64 key, base64 salt, and scrypt parameters.
   */
  async scryptDerive(password: string, salt?: Buffer): Promise<ScryptResult> {
    if (!password) {
      throw new ApiError(400, 'INVALID_PASSWORD', 'Password is required for scrypt derivation.');
    }

    const workingSalt = salt ? Buffer.from(salt) : secureBytes(DEFAULT_SALT_LENGTH);
    let derivedKey: Buffer | undefined;

    try {
      const derived = await new Promise<Buffer>((resolve, reject) => {
        scryptCallback(
          password,
          workingSalt,
          DEFAULT_DERIVED_KEY_LENGTH,
          {
            N: SCRYPT_N,
            r: SCRYPT_R,
            p: SCRYPT_P,
            maxmem: 256 * 1024 * 1024,
          },
          (error, key) => {
            if (error) {
              reject(error);
              return;
            }

            resolve(key as Buffer);
          },
        );
      });

      if (!Buffer.isBuffer(derived)) {
        throw new ApiError(500, 'SCRYPT_INVALID_RESULT', 'scrypt produced an unexpected result type.');
      }

      derivedKey = derived;

      return {
        key: derivedKey.toString('base64'),
        salt: workingSalt.toString('base64'),
        N: SCRYPT_N,
        r: SCRYPT_R,
        p: SCRYPT_P,
        algorithm: 'scrypt',
      };
    } catch (error: unknown) {
      if (error instanceof ApiError) {
        throw error;
      }

      throw new ApiError(500, 'SCRYPT_DERIVE_FAILED', 'Failed to derive key using scrypt.', error);
    } finally {
      zeroBuffer(workingSalt);
      zeroBufferIfPresent(derivedKey);
    }
  }

  /**
   * @description Expands input key material into context-bound key bytes using HKDF-SHA256.
   * @algorithm HKDF-SHA256
   * @reference RFC 5869
   * @security Input key material and salt are copied and wiped after derivation.
   * @param inputKeyMaterial Binary input key material.
   * @param info Context string for domain separation.
   * @param length Output key length in bytes.
   * @param salt Optional salt. Defaults to 32 zero bytes when omitted.
   * @returns Base64 derived key and metadata.
   */
  hkdfExpand(inputKeyMaterial: Buffer, info: string, length = DEFAULT_DERIVED_KEY_LENGTH, salt?: Buffer): HkdfResult {
    if (inputKeyMaterial.length === 0) {
      throw new ApiError(400, 'INVALID_IKM', 'Input key material is required for HKDF.');
    }

    if (!info) {
      throw new ApiError(400, 'INVALID_INFO', 'HKDF info value is required.');
    }

    if (!Number.isInteger(length) || length < 16 || length > 64) {
      throw new ApiError(400, 'INVALID_KEY_LENGTH', 'HKDF output length must be an integer between 16 and 64 bytes.');
    }

    const ikm = Buffer.from(inputKeyMaterial);
    const workingSalt = salt ? Buffer.from(salt) : Buffer.alloc(32, 0);
    let derivedKey: Buffer | undefined;

    try {
      const expanded = hkdfSync('sha256', ikm, workingSalt, info, length);
      derivedKey = Buffer.from(expanded);

      return {
        key: derivedKey.toString('base64'),
        algorithm: 'HKDF-SHA256',
        outputLength: length,
      };
    } catch (error: unknown) {
      throw new ApiError(500, 'HKDF_EXPAND_FAILED', 'Failed to expand key material with HKDF-SHA256.', error);
    } finally {
      zeroBuffer(ikm);
      zeroBuffer(workingSalt);
      zeroBufferIfPresent(derivedKey);
    }
  }

  /**
   * @description Generic derive dispatcher for supported KDF algorithms.
   * @algorithm bcrypt | argon2id | pbkdf2 | scrypt | hkdf
   * @reference RFC 9106; NIST SP 800-132; RFC 7914; RFC 5869
   * @security Validates required parameters per algorithm before derivation.
   * @param algorithm KDF algorithm selector.
   * @param options Algorithm-specific options.
   * @returns KDF result object for selected algorithm.
   */
  async derive(
    algorithm: KdfAlgorithm,
    options: {
      password?: string;
      rounds?: number;
      iterations?: number;
      keyLength?: number;
      salt?: Buffer;
      inputKeyMaterial?: Buffer;
      info?: string;
    },
  ): Promise<KdfDeriveResult> {
    if (algorithm === 'bcrypt') {
      if (!options.password) {
        throw new ApiError(400, 'INVALID_PASSWORD', 'Password is required for bcrypt.');
      }

      return this.bcryptHash(options.password, options.rounds);
    }

    if (algorithm === 'argon2id') {
      if (!options.password) {
        throw new ApiError(400, 'INVALID_PASSWORD', 'Password is required for Argon2id.');
      }

      return this.argon2Hash(options.password);
    }

    if (algorithm === 'pbkdf2') {
      if (!options.password) {
        throw new ApiError(400, 'INVALID_PASSWORD', 'Password is required for PBKDF2.');
      }

      return this.pbkdf2Derive(
        options.password,
        options.salt,
        options.iterations ?? DEFAULT_PBKDF2_ITERATIONS,
        options.keyLength ?? DEFAULT_DERIVED_KEY_LENGTH,
      );
    }

    if (algorithm === 'scrypt') {
      if (!options.password) {
        throw new ApiError(400, 'INVALID_PASSWORD', 'Password is required for scrypt.');
      }

      return this.scryptDerive(options.password, options.salt);
    }

    if (algorithm === 'hkdf') {
      if (!options.inputKeyMaterial || !options.info) {
        throw new ApiError(400, 'INVALID_HKDF_INPUT', 'HKDF requires inputKeyMaterial and info.');
      }

      return this.hkdfExpand(
        options.inputKeyMaterial,
        options.info,
        options.keyLength ?? DEFAULT_DERIVED_KEY_LENGTH,
        options.salt,
      );
    }

    throw new ApiError(400, 'UNSUPPORTED_KDF_ALGORITHM', `Unsupported KDF algorithm: ${algorithm}`);
  }

  /**
   * @description Generic verify dispatcher for password hashing KDFs that support verification.
   * @algorithm bcrypt | argon2id
   * @reference RFC 9106; bcrypt spec
   * @security Avoids revealing internal hash format errors to callers.
   * @param algorithm Verification-capable KDF algorithm.
   * @param password Candidate plaintext password.
   * @param hash Stored hash value.
   * @returns Verification result with boolean validity.
   */
  async verify(algorithm: 'bcrypt' | 'argon2id', password: string, hash: string): Promise<KdfVerifyResult> {
    if (algorithm === 'bcrypt') {
      return {
        algorithm,
        valid: await this.bcryptVerify(password, hash),
      };
    }

    return {
      algorithm,
      valid: await this.argon2Verify(password, hash),
    };
  }
}

export const kdfService = new KdfService();
