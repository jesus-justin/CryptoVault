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

describe('symmetric API integration', () => {
  beforeAll(async () => {
    app = await loadApp();
  });

  it('encrypt text and decrypt returns matching plaintext', async () => {
    const encryptResponse = await request(app)
      .post('/api/v1/symmetric/encrypt')
      .send({
        plaintext: 'integration hello',
        algorithm: 'AES-256-GCM',
        passphrase: 'strong-passphrase',
      })
      .expect(200);

    expect(encryptResponse.body.success).toBe(true);

    const encrypted = encryptResponse.body.data as {
      ciphertext: string;
      iv: string;
      authTag: string;
      algorithm: string;
    };

    const decryptResponse = await request(app)
      .post('/api/v1/symmetric/decrypt')
      .send({
        ciphertext: encrypted.ciphertext,
        algorithm: encrypted.algorithm,
        passphrase: 'strong-passphrase',
        iv: encrypted.iv,
        authTag: encrypted.authTag,
      })
      .expect(200);

    expect(decryptResponse.body.success).toBe(true);
    expect(decryptResponse.body.data.plaintext).toBe('integration hello');
  });
});
