# SECURITY.md

## Section 1: Algorithm Selection Rationale

- AES-256-GCM vs AES-256-CBC: GCM provides authenticated encryption (AEAD). CBC requires a separate MAC (HMAC) to prevent padding oracle and bit-flip attacks. GCM combines encryption and authentication in one pass. CBC is legacy in this project.
- ChaCha20-Poly1305 (RFC 8439): Software-efficient alternative to AES-GCM and constant-time on CPUs without AES acceleration. Preferred for mobile, IoT, and systems without AES-NI.
- RSA-4096 vs RSA-2048: NIST SP 800-57 recommends 3072+ bits through 2030. RSA-4096 provides added margin against factorization advances.
- Ed25519 vs ECDSA P-256: Ed25519 (RFC 8032) uses deterministic signing (no random nonce), avoiding nonce-reuse failures that can leak ECDSA private keys.
- Argon2id: Password Hashing Competition winner. Combines side-channel and GPU resistance; memory-hard settings increase attacker costs significantly.
- scrypt (RFC 7914): Memory-hard KDF with N=131072 (2^17) profile as compatibility fallback when Argon2id is unavailable.
- PBKDF2-SHA256 with 600000 iterations: NIST SP 800-132 compatibility path for systems that cannot adopt modern memory-hard KDFs.

## Section 2: What this system protects against

- Brute-force password attacks via Argon2id, bcrypt, and scrypt.
- Unauthenticated ciphertext tampering via AEAD modes (AES-GCM and ChaCha20-Poly1305).
- Timing attacks on secret comparisons via timing-safe equality checks.
- Key exposure in logs or API responses via strict audit design and key zeroing.
- JWT tampering via signature verification and jti-based revocation.

## Section 3: What this system does NOT protect against

- OS-level or hardware-level side-channel attacks.
- Privileged attacker compromise of live Node.js process memory.
- Malicious browser extensions reading user-visible content.
- Weak passphrases entered by end users without policy enforcement.

## Section 4: Deprecated algorithm policy

- MD5: Collision attacks shown in 2004 (Wang et al.). Never acceptable for security use.
- SHA-1: Deprecated for signatures by NIST and practically broken via SHAttered collision work.
- AES-CBC (legacy mode): No built-in authentication; vulnerable to padding-oracle class attacks if misused.

### Policy rules

- Deprecated algorithms are exposed only for educational comparison and must display warnings.
- Legacy algorithms remain for migration/interop only and are not recommended defaults.
- New production workflows must use recommended algorithms from the metadata registry.
