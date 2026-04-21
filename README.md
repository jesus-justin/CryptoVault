# CryptoVault v2

[![CI](https://github.com/jesus-justin/CryptoVault/actions/workflows/ci.yml/badge.svg)](https://github.com/jesus-justin/CryptoVault/actions/workflows/ci.yml)

Enterprise cryptography platform featuring AES-256-GCM, RSA-4096, Ed25519, ChaCha20-Poly1305, Argon2id, scrypt, JWT/JWE, and X25519 ECDH exchange.

## Quick start (local development)

```bash
git clone https://github.com/jesus-justin/CryptoVault.git
cd CryptoVault

# Generate SSL certs for local HTTPS
mkdir -p nginx/ssl
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout nginx/ssl/key.pem \
  -out nginx/ssl/cert.pem \
  -subj "/C=US/ST=Dev/L=Local/O=CryptoVault/CN=localhost"

# Set up environment
cp .env.example .env
# Edit .env and set JWT_SECRET to a random 32+ character string

# Start with Docker (recommended)
docker compose up -d --build

# Or start locally without Docker
cd backend && npm install && npm run dev &
cd frontend && npm install && npm run dev
```

## Local HTTPS Setup

```bash
mkdir -p nginx/ssl
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout nginx/ssl/key.pem \
  -out nginx/ssl/cert.pem \
  -subj "/C=US/ST=Dev/L=Local/O=CryptoVault/CN=localhost"
```

## Running tests

```bash
cd backend
npx vitest run --coverage      # Unit + integration tests

cd frontend
npx playwright test             # E2E tests
```

## API documentation

- Local:  https://localhost/api/v1/docs
- Direct: http://localhost:3001/api/v1/docs

## Technology decisions

- AES-256-GCM: Default symmetric encryption because it is AEAD (confidentiality + integrity in one primitive).
- ChaCha20-Poly1305: AEAD alternative that performs consistently on systems without AES hardware acceleration.
- RSA-4096: Asymmetric encryption/signature option with larger security margin than legacy 2048-bit deployments.
- Ed25519: Deterministic, modern signature scheme that avoids nonce-management failures common in ECDSA misuse.
- Argon2id: Primary password hashing/KDF choice due to memory-hardness against GPU/ASIC brute force.
- scrypt/PBKDF2: Compatibility fallback paths for environments where Argon2id is unavailable.
- JWT (HS256/RS256/ES256) + JWE: Standardized token signing and optional encryption for API auth workflows.

See SECURITY.md for full rationale, threat model scope, and deprecated algorithm policy.

## System verification

Current verified checks for this workspace:

- Backend audit: 0 vulnerabilities.
- Frontend audit: 0 vulnerabilities.
- Backend typecheck: passes.
- Frontend typecheck: passes.
- Backend tests: 74/74 passing.
- Frontend E2E: 2/2 passing.

Re-run these after future changes:

```bash
cd backend
npx vitest run --coverage
npx tsc --noEmit
npm audit --audit-level=low

cd frontend
npx playwright test
npx tsc --noEmit
npm audit --audit-level=low
```

## Project structure

```text
CryptoVault/
├─ .github/
│  └─ workflows/
│     ├─ ci.yml
│     └─ security.yml
├─ backend/
│  ├─ src/
│  │  ├─ config/
│  │  ├─ controllers/
│  │  ├─ docs/
│  │  ├─ middleware/
│  │  ├─ routes/
│  │  ├─ services/
│  │  └─ types/
│  ├─ tests/
│  │  ├─ integration/
│  │  ├─ unit/
│  │  └─ setup-env.ts
│  ├─ package.json
│  ├─ tsconfig.json
│  └─ vitest.config.ts
├─ frontend/
│  ├─ playwright/
│  │  └─ e2e/
│  ├─ src/
│  │  ├─ components/
│  │  ├─ pages/
│  │  ├─ services/
│  │  └─ styles/
│  ├─ index.html
│  ├─ package.json
│  ├─ playwright.config.ts
│  ├─ tsconfig.json
│  └─ vite.config.ts
├─ nginx/
│  ├─ ssl/
│  │  └─ README.md
│  ├─ nginx.conf
│  └─ nginx-static.conf
├─ docker-compose.yml
├─ Dockerfile.backend
├─ Dockerfile.frontend
├─ SECURITY.md
└─ .env.example
```

## CI/CD badges

- [CI workflow status](https://github.com/jesus-justin/CryptoVault/actions/workflows/ci.yml)
