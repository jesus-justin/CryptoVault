import { createHash, createHmac } from 'crypto';
import { ApiError } from '../types/api.types';
import {
  AvalancheAlgorithm,
  AvalancheResult,
  HashResult,
  HmacResult,
  SupportedHashAlgorithm,
  SupportedHmacAlgorithm,
} from '../types/crypto.types';

const MD5_WARNING = 'MD5 is cryptographically broken. Never use for security.';

class HashingService {
  /**
   * @description Produces a hex digest for the given input and hash algorithm.
   * @algorithm SHA-2 | SHA-3 | MD5 (educational only)
   * @reference FIPS 180-4; FIPS 202; RFC 1321
   * @security MD5 is included for educational comparison only and always returns a warning.
   * @param input UTF-8 input to hash.
   * @param algorithm Hash algorithm identifier.
   * @returns Hash output metadata including digest hex and bit length.
   */
  hash(input: string, algorithm: SupportedHashAlgorithm): HashResult {
    if (input === undefined || input === null) {
      throw new ApiError(400, 'INVALID_INPUT', 'Input is required for hashing.');
    }

    try {
      const digest = createHash(algorithm).update(input, 'utf8').digest('hex');
      const outputBits = digest.length * 4;

      return {
        hash: digest,
        algorithm,
        inputLength: Buffer.byteLength(input, 'utf8'),
        outputBits,
        warning: this.getWarningForAlgorithm(algorithm),
      };
    } catch (error: unknown) {
      throw new ApiError(400, 'HASH_FAILED', `Failed to hash input with algorithm ${algorithm}.`, error);
    }
  }

  /**
   * @description Computes HMAC for input data with a shared secret key.
   * @algorithm HMAC-SHA256 | HMAC-SHA512
   * @reference RFC 2104
   * @security Key material should be sourced from secure storage and never logged.
   * @param input UTF-8 input string.
   * @param key Shared secret key string.
   * @param algorithm Underlying hash algorithm for HMAC.
   * @returns HMAC metadata including digest and key length.
   */
  hmac(input: string, key: string, algorithm: SupportedHmacAlgorithm): HmacResult {
    if (!key) {
      throw new ApiError(400, 'INVALID_HMAC_KEY', 'HMAC key is required.');
    }

    try {
      const digest = createHmac(algorithm, key).update(input, 'utf8').digest('hex');

      const algorithmLabel: HmacResult['algorithm'] =
        algorithm === 'sha256' ? 'HMAC-SHA256' : 'HMAC-SHA512';

      return {
        hmac: digest,
        algorithm: algorithmLabel,
        keyLength: Buffer.byteLength(key, 'utf8'),
      };
    } catch (error: unknown) {
      throw new ApiError(400, 'HMAC_FAILED', `Failed to compute HMAC using ${algorithm}.`, error);
    }
  }

  /**
   * @description Demonstrates avalanche effect by flipping one bit of the first input byte.
   * @algorithm SHA-256 | SHA3-256
   * @reference NIST hash function design principles
   * @security Educational analysis only; not a cryptographic primitive by itself.
   * @param input UTF-8 input string.
   * @param algorithm Hash algorithm to evaluate.
   * @returns Original hash, modified hash, Hamming distance, and percentage changed bits.
   */
  avalanche(input: string, algorithm: AvalancheAlgorithm): AvalancheResult {
    const originalInputBuffer = Buffer.from(input, 'utf8');
    const flippedInputBuffer =
      originalInputBuffer.length === 0 ? Buffer.from([0]) : Buffer.from(originalInputBuffer);

    flippedInputBuffer[0] ^= 1;

    const hash1 = this.hash(originalInputBuffer.toString('utf8'), algorithm).hash;
    const hash2 = this.hash(flippedInputBuffer.toString('utf8'), algorithm).hash;

    const distance = this.hammingDistanceFromHex(hash1, hash2);
    const totalBits = hash1.length * 4;

    return {
      hash1,
      hash2,
      hammingDistance: distance,
      percentage: totalBits === 0 ? 0 : (distance / totalBits) * 100,
      inputChange: '1 bit flipped',
    };
  }

  private getWarningForAlgorithm(algorithm: SupportedHashAlgorithm): string | undefined {
    if (algorithm === 'md5') {
      return MD5_WARNING;
    }

    return undefined;
  }

  private hammingDistanceFromHex(leftHex: string, rightHex: string): number {
    const left = Buffer.from(leftHex, 'hex');
    const right = Buffer.from(rightHex, 'hex');

    if (left.length !== right.length) {
      throw new ApiError(500, 'HAMMING_DISTANCE_FAILED', 'Hash lengths must match to compute Hamming distance.');
    }

    let differingBits = 0;

    for (let i = 0; i < left.length; i += 1) {
      differingBits += this.countSetBits(left[i] ^ right[i]);
    }

    return differingBits;
  }

  private countSetBits(byteValue: number): number {
    let count = 0;
    let value = byteValue;

    while (value !== 0) {
      value &= value - 1;
      count += 1;
    }

    return count;
  }
}

export const hashingService = new HashingService();
