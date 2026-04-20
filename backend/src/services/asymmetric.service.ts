import {
  constants,
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  privateDecrypt,
  publicEncrypt,
  randomUUID,
  sign,
  verify,
} from 'crypto';
import * as selfsigned from 'selfsigned';
import { ApiError } from '../types/api.types';
import { AsymmetricAlgorithm, KeyExportFormat, KeyPairResult, X509CertificateResult } from '../types/crypto.types';

type ExportedKey = string | Buffer | Record<string, unknown>;

interface SelfSignedLikeResult {
  cert: string;
  private: string;
}

class AsymmetricService {
  /**
   * @description Generates an RSA key pair with 4096-bit modulus for encryption/signature workflows.
   * @algorithm RSA-4096
   * @reference NIST SP 800-57
   * @security Keys are exported as PEM (SPKI public / PKCS8 private); private key must be protected at rest.
   * @param None.
   * @returns RSA key pair result with UUID keyId and algorithm metadata.
   */
  generateRSAKeyPair(): KeyPairResult {
    try {
      const { publicKey, privateKey } = generateKeyPairSync('rsa', {
        modulusLength: 4096,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
      });

      return {
        publicKey,
        privateKey,
        keyId: randomUUID(),
        algorithm: 'RSA-4096',
      };
    } catch (error: unknown) {
      throw new ApiError(500, 'RSA_KEYGEN_FAILED', 'Failed to generate RSA-4096 key pair.', error);
    }
  }

  /**
   * @description Encrypts plaintext with RSA-OAEP using SHA-256.
   * @algorithm RSA-4096-OAEP-SHA256
   * @reference RFC 8017 (PKCS#1 v2.2)
   * @security Uses OAEP padding; never use PKCS1 v1.5 padding for new encryption flows.
   * @param plaintext UTF-8 plaintext to encrypt.
   * @param publicKeyPem Recipient public key in PEM format.
   * @returns Base64-encoded ciphertext.
   */
  rsaEncrypt(plaintext: string, publicKeyPem: string): string {
    if (!plaintext) {
      throw new ApiError(400, 'INVALID_PLAINTEXT', 'Plaintext is required for RSA encryption.');
    }

    try {
      const encrypted = publicEncrypt(
        {
          key: publicKeyPem,
          oaepHash: 'sha256',
          padding: constants.RSA_PKCS1_OAEP_PADDING,
        },
        Buffer.from(plaintext, 'utf8'),
      );

      return encrypted.toString('base64');
    } catch (error: unknown) {
      throw new ApiError(400, 'RSA_ENCRYPT_FAILED', 'RSA encryption failed. Verify the provided public key.', error);
    }
  }

  /**
   * @description Decrypts RSA-OAEP-SHA256 ciphertext using a PEM private key.
   * @algorithm RSA-4096-OAEP-SHA256
   * @reference RFC 8017 (PKCS#1 v2.2)
   * @security Decryption fails on malformed ciphertext or wrong private key; do not leak internal error details.
   * @param ciphertext Base64-encoded ciphertext.
   * @param privateKeyPem Private key in PEM format.
   * @returns UTF-8 plaintext.
   */
  rsaDecrypt(ciphertext: string, privateKeyPem: string): string {
    if (!ciphertext) {
      throw new ApiError(400, 'INVALID_CIPHERTEXT', 'Ciphertext is required for RSA decryption.');
    }

    try {
      const decrypted = privateDecrypt(
        {
          key: privateKeyPem,
          oaepHash: 'sha256',
          padding: constants.RSA_PKCS1_OAEP_PADDING,
        },
        Buffer.from(ciphertext, 'base64'),
      );

      return decrypted.toString('utf8');
    } catch (error: unknown) {
      throw new ApiError(400, 'RSA_DECRYPT_FAILED', 'RSA decryption failed. Verify ciphertext and private key.', error);
    }
  }

  /**
   * @description Generates an ECDSA key pair on curve P-384.
   * @algorithm ECDSA P-384
   * @reference FIPS 186-5
   * @security Signature operations use SHA-384 to align with P-384 security strength.
   * @param None.
   * @returns ECDSA key pair result with UUID keyId and algorithm metadata.
   */
  generateECKeyPair(): KeyPairResult {
    try {
      const { publicKey, privateKey } = generateKeyPairSync('ec', {
        namedCurve: 'P-384',
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
      });

      return {
        publicKey,
        privateKey,
        keyId: randomUUID(),
        algorithm: 'ECDSA-P384',
      };
    } catch (error: unknown) {
      throw new ApiError(500, 'ECDSA_KEYGEN_FAILED', 'Failed to generate ECDSA P-384 key pair.', error);
    }
  }

  /**
   * @description Signs input data with ECDSA P-384 using SHA-384 digest.
   * @algorithm ECDSA P-384 with SHA-384
   * @reference FIPS 186-5
   * @security Private key must be PKCS8 PEM and securely stored.
   * @param data UTF-8 payload to sign.
   * @param privateKeyPem Private key in PEM format.
   * @returns Base64-encoded DER signature.
   */
  signEcdsaP384(data: string, privateKeyPem: string): string {
    if (!data) {
      throw new ApiError(400, 'INVALID_DATA', 'Data is required for signing.');
    }

    try {
      const signature = sign('sha384', Buffer.from(data, 'utf8'), privateKeyPem);
      return signature.toString('base64');
    } catch (error: unknown) {
      throw new ApiError(400, 'ECDSA_SIGN_FAILED', 'ECDSA signing failed. Verify private key format.', error);
    }
  }

  /**
   * @description Verifies an ECDSA P-384 signature.
   * @algorithm ECDSA P-384 with SHA-384
   * @reference FIPS 186-5
   * @security Returns boolean validity only.
   * @param data UTF-8 signed payload.
   * @param signature Base64-encoded DER signature.
   * @param publicKeyPem Public key in PEM format.
   * @returns True when signature is valid for the payload and key.
   */
  verifyEcdsaP384(data: string, signature: string, publicKeyPem: string): boolean {
    if (!data || !signature) {
      throw new ApiError(400, 'INVALID_VERIFY_INPUT', 'Data and signature are required for verification.');
    }

    try {
      return verify('sha384', Buffer.from(data, 'utf8'), publicKeyPem, Buffer.from(signature, 'base64'));
    } catch (error: unknown) {
      throw new ApiError(400, 'ECDSA_VERIFY_FAILED', 'ECDSA verification failed. Verify key/signature format.', error);
    }
  }

  /**
   * @description Generates an Ed25519 key pair.
   * @algorithm Ed25519
   * @reference RFC 8032
   * @security Ed25519 uses deterministic signing and does not require external nonce generation.
   * @param None.
   * @returns Ed25519 key pair result with UUID keyId and algorithm metadata.
   */
  generateEd25519KeyPair(): KeyPairResult {
    try {
      const { publicKey, privateKey } = generateKeyPairSync('ed25519', {
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
      });

      return {
        publicKey,
        privateKey,
        keyId: randomUUID(),
        algorithm: 'Ed25519',
      };
    } catch (error: unknown) {
      throw new ApiError(500, 'ED25519_KEYGEN_FAILED', 'Failed to generate Ed25519 key pair.', error);
    }
  }

  /**
   * @description Signs data with Ed25519 private key.
   * @algorithm Ed25519
   * @reference RFC 8032
   * @security Uses Node.js Ed25519 mode with null digest parameter as required by API contract.
   * @param data UTF-8 payload to sign.
   * @param privateKeyPem Private key in PEM format.
   * @returns Base64 signature.
   */
  signEd25519(data: string, privateKeyPem: string): string {
    if (!data) {
      throw new ApiError(400, 'INVALID_DATA', 'Data is required for signing.');
    }

    try {
      const signature = sign(null, Buffer.from(data, 'utf8'), privateKeyPem);
      return signature.toString('base64');
    } catch (error: unknown) {
      throw new ApiError(400, 'ED25519_SIGN_FAILED', 'Ed25519 signing failed. Verify private key format.', error);
    }
  }

  /**
   * @description Verifies an Ed25519 signature.
   * @algorithm Ed25519
   * @reference RFC 8032
   * @security Uses Node.js Ed25519 mode with null digest parameter; returns boolean validity only.
   * @param data UTF-8 signed payload.
   * @param signature Base64 signature.
   * @param publicKeyPem Public key in PEM format.
   * @returns True when signature is valid for payload and key.
   */
  verifyEd25519(data: string, signature: string, publicKeyPem: string): boolean {
    if (!data || !signature) {
      throw new ApiError(400, 'INVALID_VERIFY_INPUT', 'Data and signature are required for verification.');
    }

    try {
      return verify(null, Buffer.from(data, 'utf8'), publicKeyPem, Buffer.from(signature, 'base64'));
    } catch (error: unknown) {
      throw new ApiError(400, 'ED25519_VERIFY_FAILED', 'Ed25519 verification failed. Verify key/signature format.', error);
    }
  }

  /**
   * @description Generates a demo self-signed X.509 certificate.
   * @algorithm RSA 2048 + self-signed X.509
   * @reference X.509 / selfsigned package docs
   * @security Demo use only; not a substitute for production PKI issuance.
   * @param commonName Certificate common name value.
   * @returns PEM certificate, PEM private key, and SHA-256 certificate fingerprint.
   */
  generateSelfSignedCert(commonName: string): X509CertificateResult {
    const trimmedCommonName = commonName.trim();

    if (!trimmedCommonName) {
      throw new ApiError(400, 'INVALID_COMMON_NAME', 'Common name is required for certificate generation.');
    }

    try {
      const generated = selfsigned.generate(
        [{ name: 'commonName', value: trimmedCommonName }],
        {
          days: 365,
          keySize: 2048,
        },
      );

      const parsed = this.parseSelfSignedResult(generated);
      const fingerprint = createHash('sha256').update(parsed.cert, 'utf8').digest('hex');

      return {
        cert: parsed.cert,
        privateKey: parsed.private,
        fingerprint,
      };
    } catch (error: unknown) {
      throw new ApiError(500, 'CERT_GENERATION_FAILED', 'Failed to generate self-signed certificate.', error);
    }
  }

  /**
   * @description Exports a public key from PEM into PEM, DER, or JWK format.
   * @algorithm Key export conversion
   * @reference Node.js KeyObject export API
   * @security Exported key should be handled according to classification and transport policy.
   * @param pem Public key in PEM format.
   * @param format Target export format.
   * @returns Exported key as string, Buffer, or JsonWebKey.
   */
  exportPublicKey(pem: string, format: KeyExportFormat): ExportedKey {
    if (format === 'pem') {
      return pem;
    }

    try {
      const key = createPublicKey(pem);

      if (format === 'der') {
        return key.export({ type: 'spki', format: 'der' });
      }

      return key.export({ format: 'jwk' });
    } catch (error: unknown) {
      throw new ApiError(400, 'PUBLIC_KEY_EXPORT_FAILED', 'Failed to export public key in requested format.', error);
    }
  }

  /**
   * @description Exports a private key from PEM into PEM, DER, or JWK format.
   * @algorithm Key export conversion
   * @reference Node.js KeyObject export API
   * @security Never log or expose private key material beyond explicit export calls.
   * @param pem Private key in PEM format.
   * @param format Target export format.
   * @returns Exported key as string, Buffer, or JsonWebKey.
   */
  exportPrivateKey(pem: string, format: KeyExportFormat): ExportedKey {
    if (format === 'pem') {
      return pem;
    }

    try {
      const key = createPrivateKey(pem);

      if (format === 'der') {
        return key.export({ type: 'pkcs8', format: 'der' });
      }

      return key.export({ format: 'jwk' });
    } catch (error: unknown) {
      throw new ApiError(400, 'PRIVATE_KEY_EXPORT_FAILED', 'Failed to export private key in requested format.', error);
    }
  }

  /**
   * @description Generic key generation dispatcher for supported asymmetric algorithms.
   * @algorithm RSA-4096 | ECDSA P-384 | Ed25519
   * @reference NIST SP 800-57; FIPS 186-5; RFC 8032
   * @security Ensures callers use supported algorithms only.
   * @param algorithm Algorithm to generate keys for.
   * @returns Key pair result matching requested algorithm.
   */
  generateKeyPair(algorithm: AsymmetricAlgorithm): KeyPairResult {
    if (algorithm === 'RSA-4096') {
      return this.generateRSAKeyPair();
    }

    if (algorithm === 'ECDSA-P384') {
      return this.generateECKeyPair();
    }

    if (algorithm === 'Ed25519') {
      return this.generateEd25519KeyPair();
    }

    throw new ApiError(400, 'UNSUPPORTED_ALGORITHM', `Unsupported asymmetric algorithm: ${algorithm}`);
  }

  private parseSelfSignedResult(value: unknown): SelfSignedLikeResult {
    if (typeof value !== 'object' || value === null) {
      throw new ApiError(500, 'CERT_GENERATION_INVALID_RESULT', 'Invalid certificate generation result payload.');
    }

    const record = value as Record<string, unknown>;
    const cert = record.cert;
    const privateKey = record.private;

    if (typeof cert !== 'string' || typeof privateKey !== 'string') {
      throw new ApiError(500, 'CERT_GENERATION_INVALID_RESULT', 'Certificate generation result is missing required fields.');
    }

    return {
      cert,
      private: privateKey,
    };
  }
}

export const asymmetricService = new AsymmetricService();
