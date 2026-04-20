import { Router } from 'express';
import { z } from 'zod';
import { hashAvalanche, hashData, hmacData } from '../controllers/hashing.controller';
import { validateBody } from '../middleware/inputValidator';

const hashingRouter = Router();

const hashSchema = z.object({
  input: z.string(),
  algorithm: z.enum(['sha256', 'sha512', 'sha3-256', 'sha3-512', 'md5']),
});

const hmacSchema = z.object({
  input: z.string(),
  key: z.string().min(1),
  algorithm: z.enum(['sha256', 'sha512']),
});

const avalancheSchema = z.object({
  input: z.string(),
  algorithm: z.enum(['sha256', 'sha3-256']),
});

hashingRouter.post('/', validateBody(hashSchema), hashData);
hashingRouter.post('/hmac', validateBody(hmacSchema), hmacData);
hashingRouter.post('/avalanche', validateBody(avalancheSchema), hashAvalanche);

export default hashingRouter;
