import { createCipheriv, createDecipheriv, hkdfSync } from 'crypto';
import { ApiError } from '../types/api.types';
import { SymmetricAlgorithm, SymmetricDecryptResult, SymmetricEncryptResult } from '../types/crypto.types';
import { secureBytes } from '../utils/secureBytes';
import { zeroBuffer } from '../utils/zeroBuffer';

const AES_256_KEY_LENGTH = 32;
const GCM_IV_LENGTH = 12;
const CBC_IV_LENGTH = 16;
const CHACHA_NONCE_LENGTH = 12;
const AUTH_TAG_LENGTH = 16;
const CBC_WARNING = 'CBC mode has no authentication. Use AES-256-GCM instead.';

class SymmetricService {
  /**
   * @description Generates a 256-bit symmetric key for AES-256-GCM and ChaCha20-Poly1305.
   * @algorithm CSPRNG key generation (32 bytes)
   * @reference NIST SP 800-38D; RFC 8439
   * @security Uses cryptographically secure randomness only.
   * @param None.
   * @returns Buffer containing a 32-byte key.
   */
  generateKey(): Buffer {
    return secureBytes(AES_256_KEY_LENGTH);
  }

  /**
   * @description Derives a 256-bit key from a passphrase using HKDF-SHA256.
   * @algorithm HKDF-SHA256
   * @reference RFC 5869
   * @security Never uses passphrase directly as cipher key; passphrase bytes are zeroed after derivation.
   * @param passphrase User-provided passphrase.
   * @param salt Optional salt buffer. When omitted, a zero-filled 32-byte salt is used for deterministic derivation.
   * @returns Buffer containing a 32-byte derived key.
   */
  deriveKeyFromPassphrase(passphrase: string, salt?: Buffer): Buffer {
    if (!passphrase) {
      throw new ApiError(400, 'INVALID_PASSPHRASE', 'Passphrase is required.');
    }

    const passphraseBuffer = Buffer.from(passphrase, 'utf8');
    const derivedSalt = salt ? Buffer.from(salt) : Buffer.alloc(32, 0);

    try {
      const derived = hkdfSync('sha256', passphraseBuffer, derivedSalt, 'CryptoVault-v2', AES_256_KEY_LENGTH);
      return Buffer.from(derived);
    } finally {
      zeroBuffer(passphraseBuffer);
      if (!salt) {
        zeroBuffer(derivedSalt);
      }
    }
  }

  /**
   * @description Encrypts plaintext using the selected symmetric algorithm.
   * @algorithm AES-256-GCM | ChaCha20-Poly1305 | AES-256-CBC
   * @reference NIST SP 800-38D; RFC 8439; NIST SP 800-38A
   * @security CBC mode is legacy and includes a warning because it is unauthenticated.
   * @param plaintext UTF-8 plaintext string.
   * @param key Symmetric key buffer.
   * @param algorithm Selected symmetric algorithm.
   * @returns Ciphertext package including IV/nonce and auth tag where applicable.
   */
  encrypt(plaintext: string, key: Buffer, algorithm: SymmetricAlgorithm): SymmetricEncryptResult {
    if (plaintext.length === 0) {
      throw new ApiError(400, 'INVALID_PLAINTEXT', 'Plaintext must not be empty.');
    }

    switch (algorithm) {
      case 'AES-256-GCM':
        return this.encryptAesGcm(plaintext, key);
      case 'ChaCha20-Poly1305':
        return this.encryptChaCha20Poly1305(plaintext, key);
      case 'AES-256-CBC':
        return this.encryptAesCbc(plaintext, key);
      default:
        throw new ApiError(400, 'UNSUPPORTED_ALGORITHM', `Unsupported algorithm: ${algorithm}`);
    }
  }

  /**
   * @description Decrypts ciphertext using the selected symmetric algorithm.
   * @algorithm AES-256-GCM | ChaCha20-Poly1305 | AES-256-CBC
   * @reference NIST SP 800-38D; RFC 8439; NIST SP 800-38A
   * @security GCM/ChaCha require valid auth tags; CBC mode is legacy and returns warning.
   * @param ciphertext Base64 ciphertext.
   * @param key Symmetric key buffer.
   * @param algorithm Selected symmetric algorithm.
   * @param ivOrNonce Base64 IV (AES) or nonce (ChaCha20).
   * @param authTag Base64 auth tag for AEAD modes.
   * @returns Decrypted plaintext result.
   */
  decrypt(
    ciphertext: string,
    key: Buffer,
    algorithm: SymmetricAlgorithm,
    ivOrNonce: string,
    authTag?: string,
  ): SymmetricDecryptResult {
    if (!ciphertext) {
      throw new ApiError(400, 'INVALID_CIPHERTEXT', 'Ciphertext is required.');
    }

    if (!ivOrNonce) {
      throw new ApiError(400, 'INVALID_IV_OR_NONCE', 'IV/nonce is required.');
    }

    switch (algorithm) {
      case 'AES-256-GCM':
        if (!authTag) {
          throw new ApiError(400, 'MISSING_AUTH_TAG', 'Auth tag is required for AES-256-GCM.');
        }
        return this.decryptAesGcm(ciphertext, key, ivOrNonce, authTag);
      case 'ChaCha20-Poly1305':
        if (!authTag) {
          throw new ApiError(400, 'MISSING_AUTH_TAG', 'Auth tag is required for ChaCha20-Poly1305.');
        }
        return this.decryptChaCha20Poly1305(ciphertext, key, ivOrNonce, authTag);
      case 'AES-256-CBC':
        return this.decryptAesCbc(ciphertext, key, ivOrNonce);
      default:
        throw new ApiError(400, 'UNSUPPORTED_ALGORITHM', `Unsupported algorithm: ${algorithm}`);
    }
  }

  /**
   * @description Encrypts plaintext using AES-256-GCM with a 96-bit IV and 128-bit auth tag.
   * @algorithm AES-256-GCM
   * @reference NIST SP 800-38D
   * @security Auth tag must be stored and verified during decryption.
   * @param plaintext UTF-8 plaintext.
   * @param key 32-byte AES key.
   * @returns Ciphertext, IV, auth tag, and algorithm metadata.
   */
  encryptAesGcm(plaintext: string, key: Buffer): SymmetricEncryptResult {
    this.assertKeyLength(key, AES_256_KEY_LENGTH, 'AES-256-GCM');

    const workingKey = Buffer.from(key);
    const iv = secureBytes(GCM_IV_LENGTH);

    try {
      const cipher = createCipheriv('aes-256-gcm', workingKey, iv);
      const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
      const tag = cipher.getAuthTag();

      return {
        ciphertext: ciphertext.toString('base64'),
        iv: iv.toString('base64'),
        authTag: tag.toString('base64'),
        algorithm: 'AES-256-GCM',
      };
    } catch (error: unknown) {
      throw new ApiError(500, 'AES_GCM_ENCRYPT_FAILED', 'Failed to encrypt data using AES-256-GCM.', error);
    } finally {
      zeroBuffer(workingKey);
      zeroBuffer(iv);
    }
  }

  /**
   * @description Decrypts AES-256-GCM ciphertext and verifies authentication tag.
   * @algorithm AES-256-GCM
   * @reference NIST SP 800-38D
   * @security Decryption fails if auth tag is invalid or ciphertext is tampered.
   * @param ciphertext Base64 ciphertext.
   * @param key 32-byte AES key.
   * @param iv Base64 IV.
   * @param authTag Base64 auth tag.
   * @returns Decrypted plaintext and algorithm metadata.
   */
  decryptAesGcm(ciphertext: string, key: Buffer, iv: string, authTag: string): SymmetricDecryptResult {
    this.assertKeyLength(key, AES_256_KEY_LENGTH, 'AES-256-GCM');

    const workingKey = Buffer.from(key);
    const ivBuffer = Buffer.from(iv, 'base64');
    const authTagBuffer = Buffer.from(authTag, 'base64');

    this.assertBufferLength(ivBuffer, GCM_IV_LENGTH, 'IV must be 12 bytes for AES-256-GCM.');
    this.assertBufferLength(authTagBuffer, AUTH_TAG_LENGTH, 'Auth tag must be 16 bytes for AES-256-GCM.');

    try {
      const decipher = createDecipheriv('aes-256-gcm', workingKey, ivBuffer);
      decipher.setAuthTag(authTagBuffer);

      const plaintext = Buffer.concat([
        decipher.update(Buffer.from(ciphertext, 'base64')),
        decipher.final(),
      ]).toString('utf8');

      return {
        plaintext,
        algorithm: 'AES-256-GCM',
      };
    } catch {
      throw new ApiError(400, 'AES_GCM_DECRYPT_FAILED', 'Failed to decrypt or authenticate AES-256-GCM ciphertext.');
    } finally {
      zeroBuffer(workingKey);
      zeroBuffer(ivBuffer);
      zeroBuffer(authTagBuffer);
    }
  }

  /**
   * @description Encrypts plaintext using ChaCha20-Poly1305 with a 96-bit nonce.
   * @algorithm ChaCha20-Poly1305
   * @reference RFC 8439
   * @security Requires 32-byte key and returns 128-bit auth tag.
   * @param plaintext UTF-8 plaintext.
   * @param key 32-byte ChaCha20 key.
   * @returns Ciphertext, nonce, auth tag, and algorithm metadata.
   */
  encryptChaCha20Poly1305(plaintext: string, key: Buffer): SymmetricEncryptResult {
    this.assertKeyLength(key, AES_256_KEY_LENGTH, 'ChaCha20-Poly1305');

    const workingKey = Buffer.from(key);
    const nonce = secureBytes(CHACHA_NONCE_LENGTH);

    try {
      const cipher = createCipheriv('chacha20-poly1305', workingKey, nonce, { authTagLength: AUTH_TAG_LENGTH });
      const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
      const tag = cipher.getAuthTag();

      return {
        ciphertext: ciphertext.toString('base64'),
        nonce: nonce.toString('base64'),
        authTag: tag.toString('base64'),
        algorithm: 'ChaCha20-Poly1305',
      };
    } catch (error: unknown) {
      throw new ApiError(
        500,
        'CHACHA20_ENCRYPT_FAILED',
        'Failed to encrypt data using ChaCha20-Poly1305.',
        error,
      );
    } finally {
      zeroBuffer(workingKey);
      zeroBuffer(nonce);
    }
  }

  /**
   * @description Decrypts ChaCha20-Poly1305 ciphertext and verifies authentication tag.
   * @algorithm ChaCha20-Poly1305
   * @reference RFC 8439
   * @security Decryption fails if auth tag validation fails.
   * @param ciphertext Base64 ciphertext.
   * @param key 32-byte ChaCha20 key.
   * @param nonce Base64 nonce.
   * @param authTag Base64 auth tag.
   * @returns Decrypted plaintext and algorithm metadata.
   */
  decryptChaCha20Poly1305(
    ciphertext: string,
    key: Buffer,
    nonce: string,
    authTag: string,
  ): SymmetricDecryptResult {
    this.assertKeyLength(key, AES_256_KEY_LENGTH, 'ChaCha20-Poly1305');

    const workingKey = Buffer.from(key);
    const nonceBuffer = Buffer.from(nonce, 'base64');
    const authTagBuffer = Buffer.from(authTag, 'base64');

    this.assertBufferLength(nonceBuffer, CHACHA_NONCE_LENGTH, 'Nonce must be 12 bytes for ChaCha20-Poly1305.');
    this.assertBufferLength(authTagBuffer, AUTH_TAG_LENGTH, 'Auth tag must be 16 bytes for ChaCha20-Poly1305.');

    try {
      const decipher = createDecipheriv('chacha20-poly1305', workingKey, nonceBuffer, {
        authTagLength: AUTH_TAG_LENGTH,
      });
      decipher.setAuthTag(authTagBuffer);

      const plaintext = Buffer.concat([
        decipher.update(Buffer.from(ciphertext, 'base64')),
        decipher.final(),
      ]).toString('utf8');

      return {
        plaintext,
        algorithm: 'ChaCha20-Poly1305',
      };
    } catch {
      throw new ApiError(
        400,
        'CHACHA20_DECRYPT_FAILED',
        'Failed to decrypt or authenticate ChaCha20-Poly1305 ciphertext.',
      );
    } finally {
      zeroBuffer(workingKey);
      zeroBuffer(nonceBuffer);
      zeroBuffer(authTagBuffer);
    }
  }

  /**
   * @description Encrypts plaintext using legacy AES-256-CBC mode.
   * @algorithm AES-256-CBC
   * @reference NIST SP 800-38A
   * @security CBC provides confidentiality only; it does not authenticate ciphertext.
   * @param plaintext UTF-8 plaintext.
   * @param key 32-byte AES key.
   * @returns Ciphertext package including warning message.
   */
  encryptAesCbc(plaintext: string, key: Buffer): SymmetricEncryptResult {
    this.assertKeyLength(key, AES_256_KEY_LENGTH, 'AES-256-CBC');

    const workingKey = Buffer.from(key);
    const iv = secureBytes(CBC_IV_LENGTH);

    try {
      const cipher = createCipheriv('aes-256-cbc', workingKey, iv);
      const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);

      return {
        ciphertext: ciphertext.toString('base64'),
        iv: iv.toString('base64'),
        algorithm: 'AES-256-CBC',
        warning: CBC_WARNING,
      };
    } catch (error: unknown) {
      throw new ApiError(500, 'AES_CBC_ENCRYPT_FAILED', 'Failed to encrypt data using AES-256-CBC.', error);
    } finally {
      zeroBuffer(workingKey);
      zeroBuffer(iv);
    }
  }

  /**
   * @description Decrypts legacy AES-256-CBC ciphertext.
   * @algorithm AES-256-CBC
   * @reference NIST SP 800-38A
   * @security CBC has no built-in authentication and is susceptible to tampering attacks.
   * @param ciphertext Base64 ciphertext.
   * @param key 32-byte AES key.
   * @param iv Base64 IV.
   * @returns Decrypted plaintext and warning message.
   */
  decryptAesCbc(ciphertext: string, key: Buffer, iv: string): SymmetricDecryptResult {
    this.assertKeyLength(key, AES_256_KEY_LENGTH, 'AES-256-CBC');

    const workingKey = Buffer.from(key);
    const ivBuffer = Buffer.from(iv, 'base64');

    this.assertBufferLength(ivBuffer, CBC_IV_LENGTH, 'IV must be 16 bytes for AES-256-CBC.');

    try {
      const decipher = createDecipheriv('aes-256-cbc', workingKey, ivBuffer);
      const plaintext = Buffer.concat([
        decipher.update(Buffer.from(ciphertext, 'base64')),
        decipher.final(),
      ]).toString('utf8');

      return {
        plaintext,
        algorithm: 'AES-256-CBC',
        warning: CBC_WARNING,
      };
    } catch {
      throw new ApiError(400, 'AES_CBC_DECRYPT_FAILED', 'Failed to decrypt AES-256-CBC ciphertext.');
    } finally {
      zeroBuffer(workingKey);
      zeroBuffer(ivBuffer);
    }
  }

  private assertKeyLength(key: Buffer, expectedLength: number, algorithm: SymmetricAlgorithm): void {
    if (key.length !== expectedLength) {
      throw new ApiError(
        400,
        'INVALID_KEY_LENGTH',
        `${algorithm} requires a ${expectedLength}-byte key. Received ${key.length} bytes.`,
      );
    }
  }

  private assertBufferLength(buffer: Buffer, expectedLength: number, message: string): void {
    if (buffer.length !== expectedLength) {
      throw new ApiError(400, 'INVALID_INPUT_LENGTH', message);
    }
  }
}

export const symmetricService = new SymmetricService();

export type { SymmetricDecryptResult, SymmetricEncryptResult };
