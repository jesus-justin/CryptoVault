import { describe, expect, it } from 'vitest';
import { ecdhService } from '../../src/services/ecdh.service';

describe('ecdh.service', () => {
  it('generateKeyPair returns PEM keypair', () => {
    const pair = ecdhService.generateKeyPair();

    expect(pair.publicKey).toContain('BEGIN PUBLIC KEY');
    expect(pair.privateKey).toContain('BEGIN PRIVATE KEY');
  });

  it('computeSharedSecret produces matching derived keys for Alice/Bob', () => {
    const alice = ecdhService.generateKeyPair();
    const bob = ecdhService.generateKeyPair();

    const aliceView = ecdhService.computeSharedSecret(alice.privateKey, bob.publicKey);
    const bobView = ecdhService.computeSharedSecret(bob.privateKey, alice.publicKey);

    expect(aliceView.algorithm).toBe('X25519');
    expect(bobView.algorithm).toBe('X25519');
    expect(aliceView.derivedKey).toBe(bobView.derivedKey);
    expect(aliceView.sharedSecret).toHaveLength(64);
  });

  it('fullExchangeDemo returns match true', () => {
    const demo = ecdhService.fullExchangeDemo();
    expect(demo.match).toBe(true);
    expect(demo.alice.publicKey).toContain('BEGIN PUBLIC KEY');
    expect(demo.bob.publicKey).toContain('BEGIN PUBLIC KEY');
  });

  it('computeSharedSecret throws on invalid keys', () => {
    expect(() => ecdhService.computeSharedSecret('invalid', 'invalid')).toThrow();
  });
});
