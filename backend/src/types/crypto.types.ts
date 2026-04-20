export type SymmetricAlgorithm = 'AES-256-GCM' | 'ChaCha20-Poly1305' | 'AES-256-CBC';

export interface SymmetricEncryptRequest {
  plaintext: string;
  algorithm: SymmetricAlgorithm;
  passphrase: string;
}

export interface SymmetricDecryptRequest {
  ciphertext: string;
  algorithm: SymmetricAlgorithm;
  passphrase: string;
  iv?: string;
  nonce?: string;
  authTag?: string;
}

export interface SymmetricEncryptResult {
  ciphertext: string;
  algorithm: SymmetricAlgorithm;
  iv?: string;
  nonce?: string;
  authTag?: string;
  warning?: string;
}

export interface SymmetricDecryptResult {
  plaintext: string;
  algorithm: SymmetricAlgorithm;
  warning?: string;
}

export type AsymmetricAlgorithm = 'RSA-4096' | 'ECDSA-P384' | 'Ed25519';
export type AsymmetricSignAlgorithm = 'ECDSA-P384' | 'Ed25519';
export type AsymmetricEncryptAlgorithm = 'RSA-4096';

export interface KeyPairResult {
  publicKey: string;
  privateKey: string;
  keyId: string;
  algorithm: AsymmetricAlgorithm;
}

export interface AsymmetricKeygenRequest {
  algorithm: AsymmetricAlgorithm;
}

export interface AsymmetricSignRequest {
  algorithm: AsymmetricSignAlgorithm;
  data: string;
  privateKey: string;
}

export interface AsymmetricSignResult {
  signature: string;
  algorithm: AsymmetricSignAlgorithm;
}

export interface AsymmetricVerifyRequest {
  algorithm: AsymmetricSignAlgorithm;
  data: string;
  signature: string;
  publicKey: string;
}

export interface AsymmetricVerifyResult {
  valid: boolean;
  algorithm: AsymmetricSignAlgorithm;
}

export interface AsymmetricEncryptRequest {
  algorithm: AsymmetricEncryptAlgorithm;
  plaintext: string;
  publicKey: string;
}

export interface AsymmetricEncryptResult {
  ciphertext: string;
  algorithm: AsymmetricEncryptAlgorithm;
}

export interface AsymmetricDecryptRequest {
  algorithm: AsymmetricEncryptAlgorithm;
  ciphertext: string;
  privateKey: string;
}

export interface AsymmetricDecryptResult {
  plaintext: string;
  algorithm: AsymmetricEncryptAlgorithm;
}

export interface X509CertificateResult {
  cert: string;
  privateKey: string;
  fingerprint: string;
}

export type KeyExportFormat = 'pem' | 'der' | 'jwk';

export interface ExportKeyRequest {
  pem: string;
  format: KeyExportFormat;
}

export type SupportedHashAlgorithm = 'sha256' | 'sha512' | 'sha3-256' | 'sha3-512' | 'md5';
export type SupportedHmacAlgorithm = 'sha256' | 'sha512';
export type AvalancheAlgorithm = 'sha256' | 'sha3-256';

export interface HashRequest {
  input: string;
  algorithm: SupportedHashAlgorithm;
}

export interface HashResult {
  hash: string;
  algorithm: SupportedHashAlgorithm;
  inputLength: number;
  outputBits: number;
  warning?: string;
}

export interface HmacRequest {
  input: string;
  key: string;
  algorithm: SupportedHmacAlgorithm;
}

export interface HmacResult {
  hmac: string;
  algorithm: `HMAC-${Uppercase<SupportedHmacAlgorithm>}`;
  keyLength: number;
}

export interface AvalancheRequest {
  input: string;
  algorithm: AvalancheAlgorithm;
}

export interface AvalancheResult {
  hash1: string;
  hash2: string;
  hammingDistance: number;
  percentage: number;
  inputChange: '1 bit flipped';
}

export type KdfAlgorithm = 'bcrypt' | 'argon2id' | 'pbkdf2' | 'scrypt' | 'hkdf';

export interface KdfDeriveRequest {
  algorithm: KdfAlgorithm;
  password?: string;
  passphrase?: string;
  inputKeyMaterial?: string;
  rounds?: number;
  iterations?: number;
  keyLength?: number;
  info?: string;
}

export interface KdfVerifyRequest {
  algorithm: 'bcrypt' | 'argon2id';
  password: string;
  hash: string;
}

export interface BcryptResult {
  hash: string;
  algorithm: 'bcrypt';
  rounds: number;
}

export interface Argon2Result {
  hash: string;
  algorithm: 'argon2id';
  memoryCost: number;
  timeCost: number;
  parallelism: number;
}

export interface Pbkdf2Result {
  key: string;
  salt: string;
  iterations: number;
  algorithm: 'PBKDF2-SHA256';
}

export interface ScryptResult {
  key: string;
  salt: string;
  N: number;
  r: number;
  p: number;
  algorithm: 'scrypt';
}

export interface HkdfResult {
  key: string;
  algorithm: 'HKDF-SHA256';
  outputLength: number;
}

export type KdfDeriveResult = BcryptResult | Argon2Result | Pbkdf2Result | ScryptResult | HkdfResult;

export interface KdfVerifyResult {
  algorithm: 'bcrypt' | 'argon2id';
  valid: boolean;
}

export type JwtAlgorithm = 'HS256' | 'RS256' | 'ES256';

export interface JwtSignRequest {
  payload: Record<string, unknown>;
  algorithm: JwtAlgorithm;
  secretOrPrivateKey: string;
  expiresIn?: string | number;
  issuer?: string;
  audience?: string | string[];
  subject?: string;
}

export interface JwtSignResult {
  token: string;
  algorithm: JwtAlgorithm;
  jti: string;
}

export interface JwtVerifyRequest {
  token: string;
  algorithm: JwtAlgorithm;
  secretOrPublicKey: string;
}

export interface VerifyResult {
  valid: boolean;
  error?: 'TOKEN_EXPIRED' | 'INVALID_TOKEN' | 'TOKEN_NOT_ACTIVE' | 'TOKEN_REVOKED';
  message?: string;
  expiredAt?: string;
  payload?: Record<string, unknown>;
  header?: Record<string, unknown>;
  jti?: string;
}

export interface JwtDecodeRequest {
  token: string;
}

export interface DecodedToken {
  header: Record<string, unknown> | null;
  payload: Record<string, unknown> | null;
  signature: string | null;
  isExpired: boolean;
}

export interface JwtJweRequest {
  payload: Record<string, unknown>;
  publicKey: string;
}

export interface JwtJweResult {
  token: string;
  algorithm: 'RSA-OAEP-256';
  encryption: 'A256GCM';
}

export interface JwtRevokeRequest {
  jti: string;
  expiresAt: number;
}

export interface KeyMetadata {
  keyId: string;
  algorithm: string;
  createdAt: string;
  expiresAt: string;
  rotationPolicy: 'manual' | 'auto-24h' | 'auto-7d';
}

export interface KeyEntry {
  keyId: string;
  algorithm: string;
  keyMaterial: Buffer;
  createdAt: Date;
  expiresAt: Date;
  rotationPolicy: 'manual' | 'auto-24h' | 'auto-7d';
  metadata: Record<string, string>;
}

export interface KeyVaultStoreOptions {
  ttlHours?: number;
  rotationPolicy?: 'manual' | 'auto-24h' | 'auto-7d';
  metadata?: Record<string, string>;
}

export interface ECDHKeyPair {
  publicKey: string;
  privateKey: string;
}

export interface SharedSecretResult {
  sharedSecret: string;
  derivedKey: string;
  algorithm: 'X25519';
}

export interface ECDHExchangeRequest {
  myPrivateKey: string;
  theirPublicKey: string;
}

export interface FullExchangeDemoResult {
  alice: ECDHKeyPair;
  bob: ECDHKeyPair;
  aliceSecret: SharedSecretResult;
  bobSecret: SharedSecretResult;
  match: boolean;
}

export interface HealthResponse {
  status: 'ok';
  service: string;
  version: string;
  timestamp: string;
}

export interface AlgorithmMetadataEntry {
  name: string;
  category: 'symmetric' | 'asymmetric' | 'hash' | 'kdf' | 'token' | 'key-exchange';
  status: 'recommended' | 'legacy' | 'deprecated' | 'experimental';
  reference: string;
  notes: string;
}
