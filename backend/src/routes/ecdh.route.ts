import { Router } from 'express';
import { z } from 'zod';
import { ecdhFullDemo, exchangeEcdhSecret, generateEcdhKeyPair } from '../controllers/ecdh.controller';
import { validateBody } from '../middleware/inputValidator';

const ecdhRouter = Router();

const exchangeSchema = z.object({
  myPrivateKey: z.string().min(1).optional(),
  theirPublicKey: z.string().min(1).optional(),
});

ecdhRouter.post('/keygen', generateEcdhKeyPair);
ecdhRouter.post('/exchange', validateBody(exchangeSchema), exchangeEcdhSecret);
ecdhRouter.post('/demo', ecdhFullDemo);

export default ecdhRouter;
