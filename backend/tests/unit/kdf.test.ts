import { describe, expect, it } from 'vitest';
import { kdfService } from '../../src/services/kdf.service';

describe('kdf.service', () => {
  it('bcrypt hash is not equal to password', async () => {
    const password = 'CorrectHorseBatteryStaple!';
    const result = await kdfService.bcryptHash(password);

    expect(result.hash).not.toBe(password);
  });

  it('bcrypt verify(password, hash) returns true', async () => {
    const password = 'my-password';
    const result = await kdfService.bcryptHash(password);

    const valid = await kdfService.bcryptVerify(password, result.hash);
    expect(valid).toBe(true);
  });

  it('bcrypt verify(wrongPassword, hash) returns false', async () => {
    const result = await kdfService.bcryptHash('password-1');

    const valid = await kdfService.bcryptVerify('password-2', result.hash);
    expect(valid).toBe(false);
  });

  it('Argon2id verify correct password returns true', async () => {
    const password = 'argon-password';
    const result = await kdfService.argon2Hash(password);

    const valid = await kdfService.argon2Verify(password, result.hash);
    expect(valid).toBe(true);
  });

  it('Argon2id verify wrong password returns false', async () => {
    const result = await kdfService.argon2Hash('argon-password');

    const valid = await kdfService.argon2Verify('wrong-password', result.hash);
    expect(valid).toBe(false);
  });

  it('PBKDF2 deterministic with same salt yields same output', () => {
    const salt = Buffer.alloc(32, 7);

    const first = kdfService.pbkdf2Derive('pbkdf2-password', salt, 600000, 32);
    const second = kdfService.pbkdf2Derive('pbkdf2-password', salt, 600000, 32);

    expect(first.key).toBe(second.key);
  });

  it('PBKDF2 different salts yield different outputs', () => {
    const a = kdfService.pbkdf2Derive('pbkdf2-password', Buffer.alloc(32, 1), 600000, 32);
    const b = kdfService.pbkdf2Derive('pbkdf2-password', Buffer.alloc(32, 2), 600000, 32);

    expect(a.key).not.toBe(b.key);
  });

  it('scrypt derive returns 32-byte key', async () => {
    const result = await kdfService.scryptDerive('scrypt-password');
    const key = Buffer.from(result.key, 'base64');

    expect(key.length).toBe(32);
  });

  it('HKDF expand returns requested output length', () => {
    const ikm = Buffer.from('input-key-material');
    const result = kdfService.hkdfExpand(ikm, 'test-context', 48);
    const key = Buffer.from(result.key, 'base64');

    expect(result.algorithm).toBe('HKDF-SHA256');
    expect(key.length).toBe(48);
  });

  it('derive dispatcher supports pbkdf2 and hkdf', async () => {
    const pbkdf2 = await kdfService.derive('pbkdf2', {
      password: 'dispatch-password',
      iterations: 600000,
      keyLength: 32,
    });

    const hkdf = await kdfService.derive('hkdf', {
      inputKeyMaterial: Buffer.from('dispatch-ikm'),
      info: 'dispatch-info',
      keyLength: 32,
    });

    expect(pbkdf2.algorithm).toBe('PBKDF2-SHA256');
    expect(hkdf.algorithm).toBe('HKDF-SHA256');
  });

  it('verify dispatcher supports bcrypt and argon2id', async () => {
    const bcryptHash = await kdfService.bcryptHash('dispatcher-bcrypt');
    const argonHash = await kdfService.argon2Hash('dispatcher-argon');

    const bcryptVerify = await kdfService.verify('bcrypt', 'dispatcher-bcrypt', bcryptHash.hash);
    const argonVerify = await kdfService.verify('argon2id', 'dispatcher-argon', argonHash.hash);

    expect(bcryptVerify.valid).toBe(true);
    expect(argonVerify.valid).toBe(true);
  });

  it('throws for invalid pbkdf2 iteration and key length', () => {
    expect(() => kdfService.pbkdf2Derive('pw', undefined, 10, 32)).toThrow();
    expect(() => kdfService.pbkdf2Derive('pw', undefined, 600000, 8)).toThrow();
  });

  it('throws for invalid hkdf input', () => {
    expect(() => kdfService.hkdfExpand(Buffer.alloc(0), 'ctx', 32)).toThrow();
    expect(() => kdfService.hkdfExpand(Buffer.from('ikm'), '', 32)).toThrow();
  });

  it('derive dispatcher throws for missing required options', async () => {
    await expect(kdfService.derive('bcrypt', {})).rejects.toThrow();
    await expect(kdfService.derive('hkdf', { info: 'x' })).rejects.toThrow();
  });
});
