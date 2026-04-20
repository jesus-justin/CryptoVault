import { describe, expect, it } from 'vitest';
import { symmetricService } from '../../src/services/symmetric.service';

describe('symmetric.service', () => {
  const plaintext = 'Hello CryptoVault';

  it('AES-256-GCM encrypt -> decrypt round trip returns original plaintext', () => {
    const key = symmetricService.generateKey();
    const encrypted = symmetricService.encryptAesGcm(plaintext, key);
    const decrypted = symmetricService.decryptAesGcm(
      encrypted.ciphertext,
      key,
      encrypted.iv ?? '',
      encrypted.authTag ?? '',
    );

    expect(decrypted.plaintext).toBe(plaintext);
  });

  it('AES-256-GCM decryption with wrong key throws error', () => {
    const key = symmetricService.generateKey();
    const wrongKey = symmetricService.generateKey();
    const encrypted = symmetricService.encryptAesGcm(plaintext, key);

    expect(() => {
      symmetricService.decryptAesGcm(
        encrypted.ciphertext,
        wrongKey,
        encrypted.iv ?? '',
        encrypted.authTag ?? '',
      );
    }).toThrow();
  });

  it('AES-256-GCM decryption with tampered authTag throws error', () => {
    const key = symmetricService.generateKey();
    const encrypted = symmetricService.encryptAesGcm(plaintext, key);

    const tamperedTag = Buffer.from(encrypted.authTag ?? '', 'base64');
    tamperedTag[0] ^= 0xff;

    expect(() => {
      symmetricService.decryptAesGcm(
        encrypted.ciphertext,
        key,
        encrypted.iv ?? '',
        tamperedTag.toString('base64'),
      );
    }).toThrow();
  });

  it('AES-256-GCM two encryptions of same plaintext produce different ciphertexts', () => {
    const key = symmetricService.generateKey();
    const first = symmetricService.encryptAesGcm(plaintext, key);
    const second = symmetricService.encryptAesGcm(plaintext, key);

    expect(first.ciphertext).not.toBe(second.ciphertext);
    expect(first.iv).not.toBe(second.iv);
  });

  it('ChaCha20-Poly1305 encrypt -> decrypt round trip', () => {
    const key = symmetricService.generateKey();
    const encrypted = symmetricService.encryptChaCha20Poly1305(plaintext, key);
    const decrypted = symmetricService.decryptChaCha20Poly1305(
      encrypted.ciphertext,
      key,
      encrypted.nonce ?? '',
      encrypted.authTag ?? '',
    );

    expect(decrypted.plaintext).toBe(plaintext);
  });

  it('AES-256-CBC encrypt -> decrypt round trip includes warning', () => {
    const key = symmetricService.generateKey();
    const encrypted = symmetricService.encryptAesCbc(plaintext, key);
    const decrypted = symmetricService.decryptAesCbc(encrypted.ciphertext, key, encrypted.iv ?? '');

    expect(decrypted.plaintext).toBe(plaintext);
    expect(encrypted.warning).toContain('CBC mode has no authentication');
    expect(decrypted.warning).toContain('CBC mode has no authentication');
  });

  it('throws on invalid key length for AES-256-GCM', () => {
    expect(() => {
      symmetricService.encryptAesGcm('abc', Buffer.alloc(16));
    }).toThrow();
  });

  it('throws when decrypt called without required auth tag for GCM', () => {
    const key = symmetricService.generateKey();
    const encrypted = symmetricService.encryptAesGcm('abc', key);

    expect(() => {
      symmetricService.decrypt(encrypted.ciphertext, key, 'AES-256-GCM', encrypted.iv ?? '');
    }).toThrow();
  });

  it('throws on unsupported algorithm dispatch', () => {
    const key = symmetricService.generateKey();
    expect(() => {
      symmetricService.encrypt('abc', key, 'AES-512-GCM' as unknown as 'AES-256-GCM');
    }).toThrow();
  });
});
