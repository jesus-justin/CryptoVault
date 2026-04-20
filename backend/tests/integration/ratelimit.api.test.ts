import request from 'supertest';
import { beforeAll, describe, expect, it } from 'vitest';

let app: Awaited<ReturnType<typeof loadApp>>;

async function loadApp() {
  process.env.NODE_ENV = 'test';
  process.env.PORT = '3001';
  process.env.JWT_SECRET = 'x'.repeat(64);
  process.env.ALLOWED_ORIGINS = 'http://localhost:5173';
  process.env.LOG_LEVEL = 'info';
  process.env.KEY_VAULT_TTL_HOURS = '24';

  const module = await import('../../src/server');
  return module.default;
}

describe('rate limit API integration', () => {
  beforeAll(async () => {
    app = await loadApp();
  });

  it('/api/v1/kdf/derive 21st request within 15 minutes returns 429 and Retry-After header', async () => {
    let response = await request(app)
      .post('/api/v1/kdf/derive')
      .send({ algorithm: 'bcrypt', password: 'rate-limit-password', rounds: 10 })
      .expect(200);

    for (let i = 0; i < 19; i += 1) {
      response = await request(app)
        .post('/api/v1/kdf/derive')
        .send({ algorithm: 'bcrypt', password: `rate-limit-password-${i}`, rounds: 10 });

      if (response.status !== 200) {
        break;
      }
    }

    const finalResponse = await request(app)
      .post('/api/v1/kdf/derive')
      .send({ algorithm: 'bcrypt', password: 'rate-limit-password-final', rounds: 10 });

    expect(finalResponse.status).toBe(429);
    expect(finalResponse.headers['retry-after']).toBeDefined();
  });
});
