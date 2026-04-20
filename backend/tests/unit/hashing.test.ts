import { describe, expect, it } from 'vitest';
import { hashingService } from '../../src/services/hashing.service';

describe('hashing.service', () => {
  it('SHA-256 known vector hash("abc")', () => {
    const result = hashingService.hash('abc', 'sha256');
    expect(result.hash).toBe('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  });

  it('SHA3-256 known vector hash("abc")', () => {
    const result = hashingService.hash('abc', 'sha3-256');
    expect(result.hash).toBe('3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532');
  });

  it('MD5 response includes warning field', () => {
    const result = hashingService.hash('abc', 'md5');
    expect(result.warning).toBe('MD5 is cryptographically broken. Never use for security.');
  });

  it('HMAC-SHA256 same key + data always produces same HMAC', () => {
    const a = hashingService.hmac('payload', 'shared-key', 'sha256');
    const b = hashingService.hmac('payload', 'shared-key', 'sha256');

    expect(a.hmac).toBe(b.hmac);
  });

  it('HMAC with different keys produces different HMACs', () => {
    const a = hashingService.hmac('payload', 'key-1', 'sha256');
    const b = hashingService.hmac('payload', 'key-2', 'sha256');

    expect(a.hmac).not.toBe(b.hmac);
  });

  it('Avalanche effect is near 50% bit changes for 1-bit input flip', () => {
    const result = hashingService.avalanche('Hello avalanche', 'sha256');

    expect(result.hammingDistance).toBeGreaterThan(0);
    expect(result.percentage).toBeGreaterThan(35);
    expect(result.percentage).toBeLessThan(65);
  });
});
