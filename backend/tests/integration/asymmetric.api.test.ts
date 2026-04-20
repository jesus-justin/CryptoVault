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

describe('asymmetric API integration', () => {
  beforeAll(async () => {
    app = await loadApp();
  });

  it('RSA keygen and encrypt/decrypt round trip', async () => {
    const keygen = await request(app)
      .post('/api/v1/asymmetric/keygen')
      .send({ algorithm: 'RSA-4096' })
      .expect(200);

    const keys = keygen.body.data as { publicKey: string; privateKey: string };

    const encrypted = await request(app)
      .post('/api/v1/asymmetric/encrypt')
      .send({ algorithm: 'RSA-4096', plaintext: 'hello-rsa', publicKey: keys.publicKey })
      .expect(200);

    const decrypted = await request(app)
      .post('/api/v1/asymmetric/decrypt')
      .send({ algorithm: 'RSA-4096', ciphertext: encrypted.body.data.ciphertext, privateKey: keys.privateKey })
      .expect(200);

    expect(decrypted.body.data.plaintext).toBe('hello-rsa');
  });

  it('Ed25519 sign and verify returns true', async () => {
    const keygen = await request(app)
      .post('/api/v1/asymmetric/keygen')
      .send({ algorithm: 'Ed25519' })
      .expect(200);

    const keys = keygen.body.data as { publicKey: string; privateKey: string };

    const sign = await request(app)
      .post('/api/v1/asymmetric/sign')
      .send({ algorithm: 'Ed25519', data: 'payload', privateKey: keys.privateKey })
      .expect(200);

    const verify = await request(app)
      .post('/api/v1/asymmetric/verify')
      .send({
        algorithm: 'Ed25519',
        data: 'payload',
        signature: sign.body.data.signature,
        publicKey: keys.publicKey,
      })
      .expect(200);

    expect(verify.body.data.valid).toBe(true);
  });
});
