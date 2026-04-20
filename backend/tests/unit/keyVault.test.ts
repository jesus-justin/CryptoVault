import { describe, expect, it } from 'vitest';
import { keyVaultService } from '../../src/services/keyVault.service';
import { secureBytes } from '../../src/utils/secureBytes';

describe('keyVault.service', () => {
  it('store returns keyId and does not return key material', () => {
    const keyId = keyVaultService.store('AES-256-GCM', secureBytes(32));

    expect(typeof keyId).toBe('string');
    expect(keyId.length).toBeGreaterThan(10);
  });

  it('retrieve returns correct key material for valid keyId', () => {
    const keyMaterial = secureBytes(32);
    const keyId = keyVaultService.store('AES-256-GCM', keyMaterial);

    const retrieved = keyVaultService.retrieve(keyId);
    expect(Buffer.compare(retrieved, keyMaterial)).toBe(0);
  });

  it('retrieve throws for unknown keyId', () => {
    expect(() => keyVaultService.retrieve('unknown-key-id')).toThrow();
  });

  it('retrieve throws for expired keyId', () => {
    const keyId = keyVaultService.store('AES-256-GCM', secureBytes(32), { ttlHours: -1 });
    expect(() => keyVaultService.retrieve(keyId)).toThrow();
  });

  it('rotate generates new key material for same keyId', () => {
    const keyId = keyVaultService.store('AES-256-GCM', secureBytes(32));
    const before = keyVaultService.retrieve(keyId);

    const rotatedId = keyVaultService.rotate(keyId);
    const after = keyVaultService.retrieve(rotatedId);

    expect(rotatedId).toBe(keyId);
    expect(Buffer.compare(before, after)).not.toBe(0);
  });

  it('list returns metadata only with no keyMaterial field', () => {
    const keyId = keyVaultService.store('AES-256-GCM', secureBytes(32));
    const list = keyVaultService.list();
    const item = list.find((entry) => entry.keyId === keyId);

    expect(item).toBeDefined();
    expect(item).not.toHaveProperty('keyMaterial');
  });

  it('delete removes key and it is unretrievable after deletion', () => {
    const keyId = keyVaultService.store('AES-256-GCM', secureBytes(32));

    keyVaultService.deleteKey(keyId);

    expect(() => keyVaultService.retrieve(keyId)).toThrow();
  });

  it('list excludes archived entries created during rotation', () => {
    const keyId = keyVaultService.store('AES-256-GCM', secureBytes(32));
    keyVaultService.rotate(keyId);

    const list = keyVaultService.list();
    expect(list.some((entry) => entry.keyId.includes(':archived:'))).toBe(false);
  });

  it('audit trail captures lifecycle operations', () => {
    const keyId = keyVaultService.store('AES-256-GCM', secureBytes(32));
    keyVaultService.retrieve(keyId);
    keyVaultService.deleteKey(keyId);

    const trail = keyVaultService.getAuditTrail();
    const ops = trail.filter((entry) => entry.keyId === keyId).map((entry) => entry.op);

    expect(ops).toContain('KEY_STORE');
    expect(ops).toContain('KEY_RETRIEVE');
    expect(ops).toContain('KEY_DELETE');
  });

  it('rotate throws for unknown key id', () => {
    expect(() => keyVaultService.rotate('unknown')).toThrow();
  });

  it('delete throws for unknown key id', () => {
    expect(() => keyVaultService.deleteKey('missing')).toThrow();
  });

  it('store rejects empty algorithm and empty key material', () => {
    expect(() => keyVaultService.store('   ', secureBytes(32))).toThrow();
    expect(() => keyVaultService.store('AES-256-GCM', Buffer.alloc(0))).toThrow();
  });
});
