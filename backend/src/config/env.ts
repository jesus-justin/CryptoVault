import path from 'path';
import dotenv from 'dotenv';
import { z } from 'zod';

dotenv.config({ path: path.resolve(process.cwd(), '../.env') });

export const EnvSchema = z.object({
  NODE_ENV: z.enum(['development', 'production', 'test']),
  PORT: z.string().transform(Number).pipe(z.number().min(1024).max(65535)),
  JWT_SECRET: z.string().min(32, 'JWT_SECRET must be at least 32 characters'),
  ALLOWED_ORIGINS: z.string().transform((s) => s.split(',').map((o) => o.trim())),
  LOG_LEVEL: z.enum(['error', 'warn', 'info', 'debug']).default('info'),
  TRUST_PROXY: z
    .string()
    .default('false')
    .transform((value) => value.trim().toLowerCase() === 'true'),
  REQUEST_TIMEOUT_MS: z
    .string()
    .default('10000')
    .transform(Number)
    .pipe(z.number().min(1000).max(120000)),
  SHUTDOWN_GRACE_MS: z
    .string()
    .default('10000')
    .transform(Number)
    .pipe(z.number().min(1000).max(60000)),
  KEY_VAULT_TTL_HOURS: z
    .string()
    .default('24')
    .transform(Number)
    .pipe(z.number().min(1)),
});

export type Env = z.infer<typeof EnvSchema>;

const parsedEnv = EnvSchema.safeParse(process.env);

if (!parsedEnv.success) {
  console.error('Invalid environment variables:', parsedEnv.error.flatten().fieldErrors);
  process.exit(1);
}

export const env: Env = parsedEnv.data;

console.log('Environment variables validated successfully');
