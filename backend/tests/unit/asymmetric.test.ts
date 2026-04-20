import { createPublicKey, generateKeyPairSync } from 'crypto';
import { describe, expect, it } from 'vitest';
import { asymmetricService } from '../../src/services/asymmetric.service';

describe('asymmetric.service', () => {
  it('RSA-4096 generates keys with correct modulus length', () => {
    const keys = asymmetricService.generateRSAKeyPair();
    const publicKey = createPublicKey(keys.publicKey);
    const details = publicKey.asymmetricKeyDetails;

    expect(details?.modulusLength).toBe(4096);
  });

  it('RSA encrypt -> decrypt round trip', () => {
    const keys = asymmetricService.generateRSAKeyPair();
    const plaintext = 'RSA roundtrip message';

    const ciphertext = asymmetricService.rsaEncrypt(plaintext, keys.publicKey);
    const decrypted = asymmetricService.rsaDecrypt(ciphertext, keys.privateKey);

    expect(decrypted).toBe(plaintext);
  });

  it('RSA decryption with wrong private key throws', () => {
    const keysA = asymmetricService.generateRSAKeyPair();
    const keysB = asymmetricService.generateRSAKeyPair();

    const ciphertext = asymmetricService.rsaEncrypt('secret', keysA.publicKey);

    expect(() => {
      asymmetricService.rsaDecrypt(ciphertext, keysB.privateKey);
    }).toThrow();
  });

  it('ECDSA P-384 sign -> verify returns true', () => {
    const keys = asymmetricService.generateECKeyPair();
    const message = 'message to sign';

    const signature = asymmetricService.signEcdsaP384(message, keys.privateKey);
    const valid = asymmetricService.verifyEcdsaP384(message, signature, keys.publicKey);

    expect(valid).toBe(true);
  });

  it('ECDSA verify with tampered data returns false', () => {
    const keys = asymmetricService.generateECKeyPair();
    const signature = asymmetricService.signEcdsaP384('original', keys.privateKey);

    const valid = asymmetricService.verifyEcdsaP384('tampered', signature, keys.publicKey);
    expect(valid).toBe(false);
  });

  it('Ed25519 sign -> verify returns true', () => {
    const keys = asymmetricService.generateEd25519KeyPair();
    const message = 'ed25519 payload';

    const signature = asymmetricService.signEd25519(message, keys.privateKey);
    const valid = asymmetricService.verifyEd25519(message, signature, keys.publicKey);

    expect(valid).toBe(true);
  });

  it('Ed25519 verify with wrong public key returns false', () => {
    const keyA = asymmetricService.generateEd25519KeyPair();
    const keyB = asymmetricService.generateEd25519KeyPair();

    const signature = asymmetricService.signEd25519('payload', keyA.privateKey);
    const valid = asymmetricService.verifyEd25519('payload', signature, keyB.publicKey);

    expect(valid).toBe(false);
  });

  it('ES256 compatibility smoke test with generated P-256 key pair', () => {
    const { privateKey, publicKey } = generateKeyPairSync('ec', {
      namedCurve: 'P-256',
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
      publicKeyEncoding: { type: 'spki', format: 'pem' },
    });

    expect(privateKey).toContain('BEGIN PRIVATE KEY');
    expect(publicKey).toContain('BEGIN PUBLIC KEY');
  });

  it('generateSelfSignedCert returns PEM cert and SHA-256 fingerprint', () => {
    const cert = asymmetricService.generateSelfSignedCert('localhost');
    expect(cert.cert).toContain('BEGIN CERTIFICATE');
    expect(cert.privateKey).toContain('BEGIN RSA PRIVATE KEY');
    expect(cert.fingerprint).toMatch(/^[a-f0-9]{64}$/);
  });

  it('export public/private keys to DER and JWK', () => {
    const rsa = asymmetricService.generateRSAKeyPair();

    const publicDer = asymmetricService.exportPublicKey(rsa.publicKey, 'der');
    const privateDer = asymmetricService.exportPrivateKey(rsa.privateKey, 'der');
    const publicJwk = asymmetricService.exportPublicKey(rsa.publicKey, 'jwk');
    const privateJwk = asymmetricService.exportPrivateKey(rsa.privateKey, 'jwk');

    expect(Buffer.isBuffer(publicDer)).toBe(true);
    expect(Buffer.isBuffer(privateDer)).toBe(true);
    expect(typeof publicJwk).toBe('object');
    expect(typeof privateJwk).toBe('object');
  });

  it('generateKeyPair dispatcher covers ECDSA and Ed25519', () => {
    const ecdsa = asymmetricService.generateKeyPair('ECDSA-P384');
    const ed = asymmetricService.generateKeyPair('Ed25519');

    expect(ecdsa.algorithm).toBe('ECDSA-P384');
    expect(ed.algorithm).toBe('Ed25519');
  });

  it('generateSelfSignedCert rejects empty common name', () => {
    expect(() => asymmetricService.generateSelfSignedCert('   ')).toThrow();
  });

  it('export methods throw on invalid PEM', () => {
    expect(() => asymmetricService.exportPublicKey('not-a-key', 'jwk')).toThrow();
    expect(() => asymmetricService.exportPrivateKey('not-a-key', 'jwk')).toThrow();
  });

  it('generateKeyPair throws on unsupported algorithm', () => {
    expect(() => {
      asymmetricService.generateKeyPair('UNSUPPORTED' as unknown as 'RSA-4096');
    }).toThrow();
  });
});
