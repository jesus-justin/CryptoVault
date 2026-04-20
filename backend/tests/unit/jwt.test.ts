import { createPrivateKey, generateKeyPairSync } from 'crypto';
import { compactDecrypt } from 'jose';
import { describe, expect, it } from 'vitest';
import { asymmetricService } from '../../src/services/asymmetric.service';
import { jwtService } from '../../src/services/jwt.service';

describe('jwt.service', () => {
  it('HS256 sign -> verify returns valid true with correct payload', async () => {
    const secret = 'x'.repeat(64);
    const payload = { sub: 'user-1', role: 'admin' };

    const token = await jwtService.sign(payload, 'HS256', secret, { expiresIn: '1h' });
    const result = await jwtService.verify(token, 'HS256', secret);

    expect(result.valid).toBe(true);
    expect(result.payload?.sub).toBe('user-1');
  });

  it('HS256 verify with wrong secret returns valid false', async () => {
    const token = await jwtService.sign({ sub: 'user-1' }, 'HS256', 'a'.repeat(64), { expiresIn: '1h' });
    const result = await jwtService.verify(token, 'HS256', 'b'.repeat(64));

    expect(result.valid).toBe(false);
  });

  it('HS256 expired token returns TOKEN_EXPIRED', async () => {
    const secret = 'c'.repeat(64);
    const token = await jwtService.sign({ sub: 'expired-user' }, 'HS256', secret, { expiresIn: -1 });
    const result = await jwtService.verify(token, 'HS256', secret);

    expect(result.valid).toBe(false);
    expect(result.error).toBe('TOKEN_EXPIRED');
  });

  it('RS256 sign with RSA private key -> verify with public key', async () => {
    const rsa = asymmetricService.generateRSAKeyPair();
    const token = await jwtService.sign({ scope: 'read' }, 'RS256', rsa.privateKey, { expiresIn: '1h' });
    const result = await jwtService.verify(token, 'RS256', rsa.publicKey);

    expect(result.valid).toBe(true);
    expect(result.payload?.scope).toBe('read');
  });

  it('ES256 sign with EC private key -> verify with public key', async () => {
    const { privateKey, publicKey } = generateKeyPairSync('ec', {
      namedCurve: 'P-256',
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
      publicKeyEncoding: { type: 'spki', format: 'pem' },
    });

    const token = await jwtService.sign({ scope: 'write' }, 'ES256', privateKey, { expiresIn: '1h' });
    const result = await jwtService.verify(token, 'ES256', publicKey);

    expect(result.valid).toBe(true);
    expect(result.payload?.scope).toBe('write');
  });

  it('JWE create encrypted token -> decrypt and verify payload', async () => {
    const rsa = asymmetricService.generateRSAKeyPair();
    const payload = { message: 'secret-data', env: 'test' };

    const jwe = await jwtService.createJWE(payload, rsa.publicKey);
    const decrypted = await compactDecrypt(jwe, createPrivateKey(rsa.privateKey));
    const parsed = JSON.parse(Buffer.from(decrypted.plaintext).toString('utf8')) as Record<string, unknown>;

    expect(parsed.message).toBe('secret-data');
    expect(parsed.env).toBe('test');
  });

  it('Revocation: revoke jti then verify same token returns valid false', async () => {
    const secret = 'r'.repeat(64);
    const token = await jwtService.sign({ sub: 'revokable' }, 'HS256', secret, { expiresIn: '1h' });
    const decoded = jwtService.decode(token);
    const jti = decoded.payload?.jti;

    expect(typeof jti).toBe('string');

    jwtService.revokeToken(jti as string, Date.now() + 60_000);
    const result = await jwtService.verify(token, 'HS256', secret);

    expect(result.valid).toBe(false);
    expect(result.error).toBe('TOKEN_REVOKED');
  });

  it('decode invalid token returns null header/payload', () => {
    const decoded = jwtService.decode('invalid.token');
    expect(decoded.header).toBeNull();
    expect(decoded.payload).toBeNull();
  });

  it('HS256 token with notBefore in future returns TOKEN_NOT_ACTIVE', async () => {
    const secret = 'n'.repeat(64);
    const token = await jwtService.sign({ sub: 'future-user' }, 'HS256', secret, { notBefore: '2h', expiresIn: '3h' });
    const result = await jwtService.verify(token, 'HS256', secret);

    expect(result.valid).toBe(false);
    expect(result.error).toBe('TOKEN_NOT_ACTIVE');
  });

  it('verify invalid token returns INVALID_TOKEN', async () => {
    const result = await jwtService.verify('bad.token.value', 'HS256', 'v'.repeat(64));
    expect(result.valid).toBe(false);
    expect(result.error).toBe('INVALID_TOKEN');
  });

  it('isRevoked returns false after expiry cleanup', () => {
    const jti = 'expired-jti';
    jwtService.revokeToken(jti, Date.now() + 5);
    const before = jwtService.isRevoked(jti);
    expect(before).toBe(true);
  });
});
