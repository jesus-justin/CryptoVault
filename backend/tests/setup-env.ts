process.env.NODE_ENV = process.env.NODE_ENV ?? 'test';
process.env.PORT = process.env.PORT ?? '3001';
process.env.JWT_SECRET = process.env.JWT_SECRET ?? 'x'.repeat(64);
process.env.ALLOWED_ORIGINS = process.env.ALLOWED_ORIGINS ?? 'http://localhost:5173';
process.env.LOG_LEVEL = process.env.LOG_LEVEL ?? 'debug';
process.env.KEY_VAULT_TTL_HOURS = process.env.KEY_VAULT_TTL_HOURS ?? '24';
