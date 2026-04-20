import { NextFunction, Request, Response } from 'express';
import { asymmetricService } from '../services/asymmetric.service';
import { createApiResponse } from '../types/api.types';
import {
  AsymmetricAlgorithm,
  AsymmetricDecryptRequest,
  AsymmetricEncryptRequest,
  AsymmetricSignRequest,
  AsymmetricVerifyRequest,
  KeyExportFormat,
} from '../types/crypto.types';

function resolveRequestId(res: Response): string {
  const requestId = res.locals.requestId;
  return typeof requestId === 'string' ? requestId : 'unknown';
}

/**
 * @description Generates an asymmetric key pair based on requested algorithm.
 * @algorithm RSA-4096 | ECDSA-P384 | Ed25519
 * @reference NIST SP 800-57; FIPS 186-5; RFC 8032
 * @security Private keys are returned only to caller and must be handled securely.
 * @param req Express request.
 * @param res Express response.
 * @param next Express next callback.
 * @returns Promise resolving to HTTP response.
 */
export async function generateAsymmetricKeyPair(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const { algorithm } = req.body as { algorithm: AsymmetricAlgorithm };
    const result = asymmetricService.generateKeyPair(algorithm);

    res.locals.operation = 'ASYMMETRIC_KEYGEN';
    res.locals.algorithm = algorithm;

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
 * @description Signs data with ECDSA-P384 or Ed25519.
 * @algorithm ECDSA-P384 | Ed25519
 * @reference FIPS 186-5; RFC 8032
 * @security Signature only proves integrity/authenticity when public key distribution is trusted.
 * @param req Express request.
 * @param res Express response.
 * @param next Express next callback.
 * @returns Promise resolving to HTTP response.
 */
export async function signAsymmetric(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const body = req.body as AsymmetricSignRequest;

    const signature =
      body.algorithm === 'ECDSA-P384'
        ? asymmetricService.signEcdsaP384(body.data, body.privateKey)
        : asymmetricService.signEd25519(body.data, body.privateKey);

    res.locals.operation = 'ASYMMETRIC_SIGN';
    res.locals.algorithm = body.algorithm;

    res.status(200).json(
      createApiResponse({
        success: true,
        data: {
          signature,
          algorithm: body.algorithm,
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
 * @description Verifies ECDSA-P384 or Ed25519 signature validity.
 * @algorithm ECDSA-P384 | Ed25519
 * @reference FIPS 186-5; RFC 8032
 * @security Returns boolean validity only.
 * @param req Express request.
 * @param res Express response.
 * @param next Express next callback.
 * @returns Promise resolving to HTTP response.
 */
export async function verifyAsymmetric(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const body = req.body as AsymmetricVerifyRequest;

    const valid =
      body.algorithm === 'ECDSA-P384'
        ? asymmetricService.verifyEcdsaP384(body.data, body.signature, body.publicKey)
        : asymmetricService.verifyEd25519(body.data, body.signature, body.publicKey);

    res.locals.operation = 'ASYMMETRIC_VERIFY';
    res.locals.algorithm = body.algorithm;

    res.status(200).json(
      createApiResponse({
        success: true,
        data: {
          valid,
          algorithm: body.algorithm,
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
 * @description Encrypts plaintext with RSA-4096 OAEP-SHA256.
 * @algorithm RSA-4096
 * @reference RFC 8017
 * @security Public-key encryption should be used for small payloads only.
 * @param req Express request.
 * @param res Express response.
 * @param next Express next callback.
 * @returns Promise resolving to HTTP response.
 */
export async function encryptAsymmetric(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const body = req.body as AsymmetricEncryptRequest;
    const ciphertext = asymmetricService.rsaEncrypt(body.plaintext, body.publicKey);

    res.locals.operation = 'ASYMMETRIC_ENCRYPT';
    res.locals.algorithm = body.algorithm;

    res.status(200).json(
      createApiResponse({
        success: true,
        data: {
          ciphertext,
          algorithm: body.algorithm,
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
 * @description Decrypts RSA-4096 OAEP-SHA256 ciphertext.
 * @algorithm RSA-4096
 * @reference RFC 8017
 * @security Private key use should be restricted to trusted server contexts.
 * @param req Express request.
 * @param res Express response.
 * @param next Express next callback.
 * @returns Promise resolving to HTTP response.
 */
export async function decryptAsymmetric(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const body = req.body as AsymmetricDecryptRequest;
    const plaintext = asymmetricService.rsaDecrypt(body.ciphertext, body.privateKey);

    res.locals.operation = 'ASYMMETRIC_DECRYPT';
    res.locals.algorithm = body.algorithm;

    res.status(200).json(
      createApiResponse({
        success: true,
        data: {
          plaintext,
          algorithm: body.algorithm,
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
 * @description Generates a self-signed X.509 certificate for demonstration purposes.
 * @algorithm X.509 self-signed RSA
 * @reference X.509
 * @security Demo only; not intended for production PKI trust chains.
 * @param req Express request.
 * @param res Express response.
 * @param next Express next callback.
 * @returns Promise resolving to HTTP response.
 */
export async function generateSelfSignedCertificate(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const { commonName } = req.body as { commonName: string };
    const result = asymmetricService.generateSelfSignedCert(commonName);

    res.locals.operation = 'X509_GENERATE';
    res.locals.algorithm = 'X.509';

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
 * @description Exports a public/private PEM key into PEM, DER, or JWK format.
 * @algorithm Key export conversion
 * @reference Node.js KeyObject export API
 * @security Caller is responsible for protecting private key exports.
 * @param req Express request.
 * @param res Express response.
 * @param next Express next callback.
 * @returns Promise resolving to HTTP response.
 */
export async function exportAsymmetricKey(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const body = req.body as {
      keyType: 'public' | 'private';
      pem: string;
      format: KeyExportFormat;
    };

    const exported =
      body.keyType === 'public'
        ? asymmetricService.exportPublicKey(body.pem, body.format)
        : asymmetricService.exportPrivateKey(body.pem, body.format);

    res.locals.operation = 'ASYMMETRIC_EXPORT_KEY';
    res.locals.algorithm = 'KEY_EXPORT';

    const data = Buffer.isBuffer(exported) ? exported.toString('base64') : exported;

    res.status(200).json(
      createApiResponse({
        success: true,
        data: {
          keyType: body.keyType,
          format: body.format,
          value: data,
        },
        error: null,
        requestId: resolveRequestId(res),
      }),
    );
  } catch (error: unknown) {
    next(error);
  }
}
