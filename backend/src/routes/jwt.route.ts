import { Router } from 'express';
import { z } from 'zod';
import { createJwe, decodeJwt, revokeJwt, signJwt, verifyJwt } from '../controllers/jwt.controller';
import { validateBody } from '../middleware/inputValidator';

const jwtRouter = Router();

const signSchema = z.object({
  payload: z.record(z.unknown()),
  algorithm: z.enum(['HS256', 'RS256', 'ES256']),
  secretOrPrivateKey: z.string().min(1).optional(),
  expiresIn: z.union([z.string(), z.number()]).optional(),
  issuer: z.string().optional(),
  audience: z.union([z.string(), z.array(z.string())]).optional(),
  subject: z.string().optional(),
  notBefore: z.union([z.string(), z.number()]).optional(),
});

const verifySchema = z.object({
  token: z.string().min(1),
  algorithm: z.enum(['HS256', 'RS256', 'ES256']),
  secretOrPublicKey: z.string().min(1),
});

const decodeSchema = z.object({
  token: z.string().min(1),
});

const jweSchema = z.object({
  payload: z.record(z.unknown()),
  publicKey: z.string().min(1),
});

const revokeSchema = z.object({
  jti: z.string().min(1),
  expiresAt: z.number(),
});

jwtRouter.post('/sign', validateBody(signSchema), signJwt);
jwtRouter.post('/verify', validateBody(verifySchema), verifyJwt);
jwtRouter.post('/decode', validateBody(decodeSchema), decodeJwt);
jwtRouter.post('/jwe', validateBody(jweSchema), createJwe);
jwtRouter.post('/revoke', validateBody(revokeSchema), revokeJwt);

export default jwtRouter;
