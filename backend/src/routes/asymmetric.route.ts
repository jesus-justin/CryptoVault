import { Router } from 'express';
import { z } from 'zod';
import {
  decryptAsymmetric,
  encryptAsymmetric,
  exportAsymmetricKey,
  generateAsymmetricKeyPair,
  generateSelfSignedCertificate,
  signAsymmetric,
  verifyAsymmetric,
} from '../controllers/asymmetric.controller';
import { validateBody } from '../middleware/inputValidator';

const asymmetricRouter = Router();

const keygenSchema = z.object({
  algorithm: z.enum(['RSA-4096', 'ECDSA-P384', 'Ed25519']),
});

const signSchema = z.object({
  algorithm: z.enum(['ECDSA-P384', 'Ed25519']),
  data: z.string().min(1),
  privateKey: z.string().min(1),
});

const verifySchema = z.object({
  algorithm: z.enum(['ECDSA-P384', 'Ed25519']),
  data: z.string().min(1),
  signature: z.string().min(1),
  publicKey: z.string().min(1),
});

const encryptSchema = z.object({
  algorithm: z.literal('RSA-4096'),
  plaintext: z.string().min(1),
  publicKey: z.string().min(1),
});

const decryptSchema = z.object({
  algorithm: z.literal('RSA-4096'),
  ciphertext: z.string().min(1),
  privateKey: z.string().min(1),
});

const certSchema = z.object({
  commonName: z.string().min(1),
});

const exportSchema = z.object({
  keyType: z.enum(['public', 'private']),
  pem: z.string().min(1),
  format: z.enum(['pem', 'der', 'jwk']),
});

asymmetricRouter.post('/keygen', validateBody(keygenSchema), generateAsymmetricKeyPair);
asymmetricRouter.post('/sign', validateBody(signSchema), signAsymmetric);
asymmetricRouter.post('/verify', validateBody(verifySchema), verifyAsymmetric);
asymmetricRouter.post('/encrypt', validateBody(encryptSchema), encryptAsymmetric);
asymmetricRouter.post('/decrypt', validateBody(decryptSchema), decryptAsymmetric);
asymmetricRouter.post('/cert/self-signed', validateBody(certSchema), generateSelfSignedCertificate);
asymmetricRouter.post('/export', validateBody(exportSchema), exportAsymmetricKey);

export default asymmetricRouter;
