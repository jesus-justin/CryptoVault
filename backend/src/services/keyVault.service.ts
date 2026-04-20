import { randomUUID } from 'crypto';
import { env } from '../config/env';
import { ApiError } from '../types/api.types';
import { KeyEntry, KeyMetadata, KeyVaultStoreOptions } from '../types/crypto.types';
import { secureBytes } from '../utils/secureBytes';
import { zeroBuffer } from '../utils/zeroBuffer';

interface AuditTrailEntry {
  op: 'KEY_STORE' | 'KEY_RETRIEVE' | 'KEY_ROTATE' | 'KEY_DELETE' | 'KEY_EXPIRE';
  keyId: string;
  timestamp: string;
}

const DEFAULT_TTL_HOURS = env.KEY_VAULT_TTL_HOURS;
const ARCHIVE_GRACE_HOURS = 24;
const CLEANUP_INTERVAL_MS = 5 * 60 * 1000;

class KeyVaultService {
  private readonly entries = new Map<string, KeyEntry>();
  private readonly auditTrail: AuditTrailEntry[] = [];

  constructor() {
    const cleanupTimer = setInterval(() => {
      this.cleanupExpiredKeys();
    }, CLEANUP_INTERVAL_MS);

    cleanupTimer.unref();
  }

  /**
   * @description Stores key material in an in-memory vault under a generated UUID keyId.
   * @algorithm Key vault storage (in-memory map)
   * @reference Internal CryptoVault key lifecycle policy
   * @security Never returns key material; only returns keyId.
   * @param algorithm Algorithm name associated with the key.
   * @param keyMaterial Key bytes to store.
   * @param options Optional TTL, rotation policy, and metadata.
   * @returns The generated keyId.
   */
  store(algorithm: string, keyMaterial: Buffer, options?: KeyVaultStoreOptions): string {
    if (!algorithm.trim()) {
      throw new ApiError(400, 'INVALID_ALGORITHM', 'Algorithm is required to store a key.');
    }

    if (keyMaterial.length === 0) {
      throw new ApiError(400, 'INVALID_KEY_MATERIAL', 'Key material must not be empty.');
    }

    const keyId = randomUUID();
    const now = new Date();
    const ttlHours = options?.ttlHours ?? DEFAULT_TTL_HOURS;

    const entry: KeyEntry = {
      keyId,
      algorithm,
      keyMaterial: Buffer.from(keyMaterial),
      createdAt: now,
      expiresAt: new Date(now.getTime() + ttlHours * 60 * 60 * 1000),
      rotationPolicy: options?.rotationPolicy ?? 'manual',
      metadata: options?.metadata ?? {},
    };

    this.entries.set(keyId, entry);
    this.recordAudit('KEY_STORE', keyId);

    return keyId;
  }

  /**
   * @description Retrieves active key material by keyId.
   * @algorithm Key vault retrieval
   * @reference Internal CryptoVault key lifecycle policy
   * @security Validates existence and expiration; retrieval is audit-logged.
   * @param keyId Vault key identifier.
   * @returns A copy of key material bytes.
   */
  retrieve(keyId: string): Buffer {
    const entry = this.entries.get(keyId);

    if (!entry) {
      throw new ApiError(404, 'KEY_NOT_FOUND', 'Key not found in vault.');
    }

    if (this.isExpired(entry)) {
      this.expireEntry(keyId, entry);
      throw new ApiError(410, 'KEY_EXPIRED', 'Key exists but has expired.');
    }

    this.recordAudit('KEY_RETRIEVE', keyId);
    return Buffer.from(entry.keyMaterial);
  }

  /**
   * @description Rotates key material in place while archiving the previous key for a 24-hour grace period.
   * @algorithm Key rotation with archive grace period
   * @reference NIST SP 800-57 (key lifecycle)
   * @security Old key material is retained only in archived entry with explicit expiration.
   * @param keyId Vault key identifier to rotate.
   * @returns The same keyId after rotation.
   */
  rotate(keyId: string): string {
    const entry = this.entries.get(keyId);

    if (!entry) {
      throw new ApiError(404, 'KEY_NOT_FOUND', 'Cannot rotate key that does not exist.');
    }

    if (this.isExpired(entry)) {
      this.expireEntry(keyId, entry);
      throw new ApiError(410, 'KEY_EXPIRED', 'Cannot rotate an expired key.');
    }

    const now = new Date();
    const archivedId = `${keyId}:archived:${now.getTime()}`;
    const archivedEntry: KeyEntry = {
      keyId: archivedId,
      algorithm: entry.algorithm,
      keyMaterial: Buffer.from(entry.keyMaterial),
      createdAt: entry.createdAt,
      expiresAt: new Date(now.getTime() + ARCHIVE_GRACE_HOURS * 60 * 60 * 1000),
      rotationPolicy: 'manual',
      metadata: {
        ...entry.metadata,
        archivedFrom: keyId,
      },
    };

    this.entries.set(archivedId, archivedEntry);

    const newKeyMaterial = secureBytes(this.resolveKeyLength(entry.algorithm));
    zeroBuffer(entry.keyMaterial);

    entry.keyMaterial = newKeyMaterial;
    entry.createdAt = now;
    entry.expiresAt = this.calculateExpiry(now, entry.rotationPolicy);

    this.entries.set(keyId, entry);
    this.recordAudit('KEY_ROTATE', keyId);

    return keyId;
  }

  /**
   * @description Lists metadata for active (non-archived) keys.
   * @algorithm Key metadata enumeration
   * @reference Internal CryptoVault key vault API contract
   * @security Never exposes key material.
   * @returns Array of key metadata records.
   */
  list(): KeyMetadata[] {
    const items: KeyMetadata[] = [];

    for (const [keyId, entry] of this.entries.entries()) {
      if (keyId.includes(':archived:')) {
        continue;
      }

      if (this.isExpired(entry)) {
        this.expireEntry(keyId, entry);
        continue;
      }

      items.push({
        keyId: entry.keyId,
        algorithm: entry.algorithm,
        createdAt: entry.createdAt.toISOString(),
        expiresAt: entry.expiresAt.toISOString(),
        rotationPolicy: entry.rotationPolicy,
      });
    }

    return items;
  }

  /**
   * @description Deletes a key from the vault after zeroing key bytes.
   * @algorithm Secure key deletion
   * @reference NIST SP 800-57 (key destruction guidance)
   * @security Key bytes are overwritten before map removal.
   * @param keyId Vault key identifier.
   * @returns Void.
   */
  deleteKey(keyId: string): void {
    const entry = this.entries.get(keyId);

    if (!entry) {
      throw new ApiError(404, 'KEY_NOT_FOUND', 'Cannot delete key that does not exist.');
    }

    zeroBuffer(entry.keyMaterial);
    this.entries.delete(keyId);
    this.recordAudit('KEY_DELETE', keyId);
  }

  /**
   * @description Returns audit trail entries for key lifecycle events.
   * @algorithm Audit trail retrieval
   * @reference Internal CryptoVault auditing policy
   * @security Audit records contain operation metadata only; no key material.
   * @returns Immutable audit trail snapshot.
   */
  getAuditTrail(): readonly AuditTrailEntry[] {
    return this.auditTrail;
  }

  private cleanupExpiredKeys(): void {
    for (const [keyId, entry] of this.entries.entries()) {
      if (this.isExpired(entry)) {
        this.expireEntry(keyId, entry);
      }
    }
  }

  private expireEntry(keyId: string, entry: KeyEntry): void {
    zeroBuffer(entry.keyMaterial);
    this.entries.delete(keyId);
    this.recordAudit('KEY_EXPIRE', keyId);
  }

  private calculateExpiry(now: Date, policy: KeyEntry['rotationPolicy']): Date {
    if (policy === 'auto-24h') {
      return new Date(now.getTime() + 24 * 60 * 60 * 1000);
    }

    if (policy === 'auto-7d') {
      return new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000);
    }

    return new Date(now.getTime() + DEFAULT_TTL_HOURS * 60 * 60 * 1000);
  }

  private isExpired(entry: KeyEntry): boolean {
    return entry.expiresAt.getTime() <= Date.now();
  }

  private resolveKeyLength(algorithm: string): number {
    const normalized = algorithm.trim().toUpperCase();

    if (normalized.includes('AES-256') || normalized.includes('CHACHA20') || normalized.includes('X25519')) {
      return 32;
    }

    if (normalized.includes('AES-192')) {
      return 24;
    }

    if (normalized.includes('AES-128')) {
      return 16;
    }

    return 32;
  }

  private recordAudit(op: AuditTrailEntry['op'], keyId: string): void {
    this.auditTrail.push({
      op,
      keyId,
      timestamp: new Date().toISOString(),
    });

    if (this.auditTrail.length > 5000) {
      this.auditTrail.shift();
    }
  }
}

export const keyVaultService = new KeyVaultService();
