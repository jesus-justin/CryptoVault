import { Router } from 'express';
import { z } from 'zod';
import { decryptSymmetric, encryptSymmetric } from '../controllers/symmetric.controller';
import { validateBody } from '../middleware/inputValidator';

const symmetricRouter = Router();

const encryptSchema = z.object({
  plaintext: z.string().min(1),
  algorithm: z.enum(['AES-256-GCM', 'ChaCha20-Poly1305', 'AES-256-CBC']),
  passphrase: z.string().min(1),
});

const decryptSchema = z.object({
  ciphertext: z.string().min(1),
  algorithm: z.enum(['AES-256-GCM', 'ChaCha20-Poly1305', 'AES-256-CBC']),
  passphrase: z.string().min(1),
  iv: z.string().optional(),
  nonce: z.string().optional(),
  authTag: z.string().optional(),
});

/**
 * @swagger
 * /api/v1/symmetric/encrypt:
 *   post:
 *     summary: Encrypt plaintext using a symmetric cipher
 *     tags: [Symmetric Encryption]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               plaintext:
 *                 type: string
 *                 example: Hello, World!
 *               algorithm:
 *                 type: string
 *                 enum: [AES-256-GCM, ChaCha20-Poly1305, AES-256-CBC]
 *               passphrase:
 *                 type: string
 *                 example: my-strong-passphrase
 *     responses:
 *       200:
 *         description: Encryption success response
 *       400:
 *         description: Validation error
 *       429:
 *         description: Rate limit exceeded
 *       500:
 *         description: Internal server error
 */
symmetricRouter.post('/encrypt', validateBody(encryptSchema), encryptSymmetric);

/**
 * @swagger
 * /api/v1/symmetric/decrypt:
 *   post:
 *     summary: Decrypt ciphertext using a symmetric cipher
 *     tags: [Symmetric Encryption]
 *     requestBody:
 *       required: true
 *     responses:
 *       200:
 *         description: Decryption success response
 *       400:
 *         description: Validation or authentication error
 *       429:
 *         description: Rate limit exceeded
 *       500:
 *         description: Internal server error
 */
symmetricRouter.post('/decrypt', validateBody(decryptSchema), decryptSymmetric);

export default symmetricRouter;
