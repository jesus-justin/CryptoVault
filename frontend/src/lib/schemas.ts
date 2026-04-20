import { z } from 'zod';

export const apiResponseSchema = z.object({
  success: z.boolean(),
  data: z.unknown().nullable(),
  error: z.string().nullable(),
  requestId: z.string(),
  timestamp: z.string(),
});

export const symmetricEncryptSchema = z.object({
  plaintext: z.string().min(1),
  algorithm: z.enum(['AES-256-GCM', 'ChaCha20-Poly1305', 'AES-256-CBC']),
  passphrase: z.string().min(1),
});

export const symmetricDecryptSchema = z.object({
  ciphertext: z.string().min(1),
  algorithm: z.enum(['AES-256-GCM', 'ChaCha20-Poly1305', 'AES-256-CBC']),
  passphrase: z.string().min(1),
  iv: z.string().optional(),
  nonce: z.string().optional(),
  authTag: z.string().optional(),
});

export const asymmetricKeygenSchema = z.object({
  algorithm: z.enum(['RSA-4096', 'ECDSA-P384', 'Ed25519']),
});

export const signSchema = z.object({
  algorithm: z.enum(['ECDSA-P384', 'Ed25519']),
  data: z.string().min(1),
  privateKey: z.string().min(1),
});

export const verifySchema = z.object({
  algorithm: z.enum(['ECDSA-P384', 'Ed25519']),
  data: z.string().min(1),
  signature: z.string().min(1),
  publicKey: z.string().min(1),
});

export const hashSchema = z.object({
  input: z.string(),
  algorithm: z.enum(['sha256', 'sha512', 'sha3-256', 'sha3-512', 'md5']),
});

export const hmacSchema = z.object({
  input: z.string(),
  key: z.string().min(1),
  algorithm: z.enum(['sha256', 'sha512']),
});

export const avalancheSchema = z.object({
  input: z.string(),
  algorithm: z.enum(['sha256', 'sha3-256']),
});

export const kdfDeriveSchema = z.object({
  algorithm: z.enum(['bcrypt', 'argon2id', 'pbkdf2', 'scrypt', 'hkdf']),
  password: z.string().optional(),
  rounds: z.number().optional(),
  iterations: z.number().optional(),
  keyLength: z.number().optional(),
  passphrase: z.string().optional(),
  inputKeyMaterial: z.string().optional(),
  info: z.string().optional(),
});

export const kdfVerifySchema = z.object({
  algorithm: z.enum(['bcrypt', 'argon2id']),
  password: z.string().min(1),
  hash: z.string().min(1),
});

export const jwtSignSchema = z.object({
  payload: z.record(z.unknown()),
  algorithm: z.enum(['HS256', 'RS256', 'ES256']),
  secretOrPrivateKey: z.string().min(1),
  expiresIn: z.union([z.string(), z.number()]).optional(),
});

export const jwtVerifySchema = z.object({
  token: z.string().min(1),
  algorithm: z.enum(['HS256', 'RS256', 'ES256']),
  secretOrPublicKey: z.string().min(1),
});

export const jwtDecodeSchema = z.object({
  token: z.string().min(1),
});

export const jweSchema = z.object({
  payload: z.record(z.unknown()),
  publicKey: z.string().min(1),
});

export const ecdhExchangeSchema = z.object({
  myPrivateKey: z.string().min(1),
  theirPublicKey: z.string().min(1),
});

export type ApiResponse = z.infer<typeof apiResponseSchema>;
export type SymmetricEncryptInput = z.infer<typeof symmetricEncryptSchema>;
export type SymmetricDecryptInput = z.infer<typeof symmetricDecryptSchema>;
export type AsymmetricKeygenInput = z.infer<typeof asymmetricKeygenSchema>;
export type SignInput = z.infer<typeof signSchema>;
export type VerifyInput = z.infer<typeof verifySchema>;
export type HashInput = z.infer<typeof hashSchema>;
export type HmacInput = z.infer<typeof hmacSchema>;
export type AvalancheInput = z.infer<typeof avalancheSchema>;
export type KdfDeriveInput = z.infer<typeof kdfDeriveSchema>;
export type KdfVerifyInput = z.infer<typeof kdfVerifySchema>;
export type JwtSignInput = z.infer<typeof jwtSignSchema>;
export type JwtVerifyInput = z.infer<typeof jwtVerifySchema>;
export type JwtDecodeInput = z.infer<typeof jwtDecodeSchema>;
export type JweInput = z.infer<typeof jweSchema>;
export type EcdhExchangeInput = z.infer<typeof ecdhExchangeSchema>;
