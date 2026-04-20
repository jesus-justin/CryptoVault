import { Router } from 'express';
import { z } from 'zod';
import { deriveKdf, verifyKdf } from '../controllers/kdf.controller';
import { validateBody } from '../middleware/inputValidator';

const kdfRouter = Router();

const deriveSchema = z.object({
  algorithm: z.enum(['bcrypt', 'argon2id', 'pbkdf2', 'scrypt', 'hkdf']),
  password: z.string().optional(),
  rounds: z.number().int().optional(),
  iterations: z.number().int().optional(),
  keyLength: z.number().int().optional(),
  passphrase: z.string().optional(),
  inputKeyMaterial: z.string().optional(),
  info: z.string().optional(),
});

const verifySchema = z.object({
  algorithm: z.enum(['bcrypt', 'argon2id']),
  password: z.string().min(1),
  hash: z.string().min(1),
});

kdfRouter.post('/derive', validateBody(deriveSchema), deriveKdf);
kdfRouter.post('/verify', validateBody(verifySchema), verifyKdf);

export default kdfRouter;
