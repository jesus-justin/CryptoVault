import { AlgorithmMetadataEntry } from '../types/crypto.types';

const registry: AlgorithmMetadataEntry[] = [
  {
    name: 'AES-256-GCM',
    category: 'symmetric',
    status: 'recommended',
    reference: 'NIST SP 800-38D',
    notes: 'AEAD mode with built-in authentication tag. Preferred for symmetric encryption.',
  },
  {
    name: 'ChaCha20-Poly1305',
    category: 'symmetric',
    status: 'recommended',
    reference: 'RFC 8439',
    notes: 'AEAD stream cipher with excellent software performance on non-AES-NI systems.',
  },
  {
    name: 'AES-256-CBC',
    category: 'symmetric',
    status: 'legacy',
    reference: 'NIST SP 800-38A',
    notes: 'Legacy mode without built-in authentication. Use AES-256-GCM where possible.',
  },
  {
    name: 'RSA-4096',
    category: 'asymmetric',
    status: 'recommended',
    reference: 'NIST SP 800-57',
    notes: 'High-security RSA profile for encryption and signatures with OAEP-SHA256.',
  },
  {
    name: 'ECDSA-P384',
    category: 'asymmetric',
    status: 'recommended',
    reference: 'FIPS 186-5',
    notes: 'Strong elliptic-curve signature scheme with SHA-384.',
  },
  {
    name: 'Ed25519',
    category: 'asymmetric',
    status: 'recommended',
    reference: 'RFC 8032',
    notes: 'Deterministic, modern signature algorithm with strong security and performance.',
  },
  {
    name: 'X25519',
    category: 'key-exchange',
    status: 'recommended',
    reference: 'RFC 7748',
    notes: 'Modern elliptic-curve Diffie-Hellman key exchange for shared secret derivation.',
  },
  {
    name: 'SHA-256',
    category: 'hash',
    status: 'recommended',
    reference: 'FIPS 180-4',
    notes: 'Widely accepted secure hash function for integrity and signatures.',
  },
  {
    name: 'SHA-512',
    category: 'hash',
    status: 'recommended',
    reference: 'FIPS 180-4',
    notes: 'Secure hash with larger digest output for high-security applications.',
  },
  {
    name: 'SHA3-256',
    category: 'hash',
    status: 'recommended',
    reference: 'FIPS 202',
    notes: 'Keccak-based hash family as an alternative to SHA-2.',
  },
  {
    name: 'SHA3-512',
    category: 'hash',
    status: 'recommended',
    reference: 'FIPS 202',
    notes: 'Keccak-based hash with 512-bit output.',
  },
  {
    name: 'MD5',
    category: 'hash',
    status: 'deprecated',
    reference: 'RFC 1321',
    notes: 'Cryptographically broken due to practical collision attacks. Educational use only.',
  },
  {
    name: 'Argon2id',
    category: 'kdf',
    status: 'recommended',
    reference: 'RFC 9106',
    notes: 'Memory-hard password hashing and key derivation algorithm.',
  },
  {
    name: 'scrypt',
    category: 'kdf',
    status: 'recommended',
    reference: 'RFC 7914',
    notes: 'Memory-hard KDF suitable for password-based key derivation.',
  },
  {
    name: 'PBKDF2-SHA256',
    category: 'kdf',
    status: 'legacy',
    reference: 'NIST SP 800-132',
    notes: 'Compatibility-focused KDF; use Argon2id when available.',
  },
  {
    name: 'bcrypt',
    category: 'kdf',
    status: 'legacy',
    reference: 'Provos and Mazieres (USENIX 1999)',
    notes: 'Legacy password hashing function. Prefer Argon2id for new systems.',
  },
  {
    name: 'HKDF-SHA256',
    category: 'kdf',
    status: 'recommended',
    reference: 'RFC 5869',
    notes: 'Extract-and-expand KDF for deriving context-bound keys.',
  },
  {
    name: 'HS256',
    category: 'token',
    status: 'recommended',
    reference: 'RFC 7518',
    notes: 'HMAC-SHA256 JWT signing; requires strong symmetric secret management.',
  },
  {
    name: 'RS256',
    category: 'token',
    status: 'recommended',
    reference: 'RFC 7518',
    notes: 'RSA PKCS#1 v1.5 JWT signature algorithm with asymmetric key separation.',
  },
  {
    name: 'ES256',
    category: 'token',
    status: 'recommended',
    reference: 'RFC 7518',
    notes: 'ECDSA P-256 JWT signature algorithm with compact signatures.',
  },
  {
    name: 'RSA-OAEP-256 + A256GCM',
    category: 'token',
    status: 'recommended',
    reference: 'RFC 7516',
    notes: 'JWE profile for encrypted JWT payloads using RSA key transport and AES-GCM content encryption.',
  },
];

/**
 * @description Returns all algorithm metadata entries used by the API and UI.
 * @algorithm Metadata registry lookup
 * @reference Internal CryptoVault policy
 * @security Source of truth for status labels (recommended/legacy/deprecated/experimental).
 * @returns A readonly snapshot of algorithm metadata entries.
 */
export function getAlgorithmMetadata(): readonly AlgorithmMetadataEntry[] {
  return registry;
}

/**
 * @description Finds metadata for a single algorithm name (case-insensitive).
 * @algorithm Metadata registry lookup
 * @reference Internal CryptoVault policy
 * @security Enables consistent warning generation for deprecated/legacy algorithms.
 * @param name Algorithm name.
 * @returns Matching metadata entry or null when not found.
 */
export function getAlgorithmByName(name: string): AlgorithmMetadataEntry | null {
  const normalized = name.trim().toLowerCase();
  const found = registry.find((entry) => entry.name.toLowerCase() === normalized);
  return found ?? null;
}

/**
 * @description Returns metadata entries filtered by lifecycle status.
 * @algorithm Metadata registry filtering
 * @reference Internal CryptoVault policy
 * @security Useful for highlighting risky algorithms in API and frontend views.
 * @param status Lifecycle status to filter by.
 * @returns Filtered metadata entries.
 */
export function getAlgorithmsByStatus(
  status: AlgorithmMetadataEntry['status'],
): AlgorithmMetadataEntry[] {
  return registry.filter((entry) => entry.status === status);
}
