# Enterprise Readiness Plan

## Objective
Raise CryptoVault from a strong development-grade crypto platform to an enterprise-ready platform with predictable operations, stronger supply-chain controls, and governance-friendly delivery.

## Improvements Implemented In This Change Set

### Runtime and Reliability
- Added request timeout enforcement to backend API runtime.
- Added graceful shutdown handling for `SIGINT` and `SIGTERM`.
- Added in-flight request drain behavior during shutdown.
- Added explicit liveness and readiness endpoints:
  - `GET /api/v1/live`
  - `GET /api/v1/ready`
- Added configurable trust proxy support for production reverse-proxy deployments.

### Environment and Deployment Controls
- Extended environment schema and `.env.example` with:
  - `TRUST_PROXY`
  - `REQUEST_TIMEOUT_MS`
  - `SHUTDOWN_GRACE_MS`
- Updated Docker Compose backend service to pass these controls with safe defaults.
- Added container security option `no-new-privileges` for backend and nginx services.

### Container Hardening
- Set production runtime `NODE_ENV=production` in backend image.
- Ensured built runtime assets are copied with explicit `node` ownership.

### CI/CD and Security Governance
- Upgraded CI workflow with:
  - workflow concurrency control
  - npm dependency cache usage
  - parallelized quality checks (lint + typecheck for backend/frontend)
  - backend coverage artifact publication
  - Playwright report artifact publication
  - optional Snyk scans when `SNYK_TOKEN` is configured
- Upgraded security workflow with:
  - pull request dependency-review gate
  - CodeQL static analysis
  - optional Snyk execution guard
- Added Dependabot automation for backend, frontend, and GitHub Actions dependencies.

## Next Enterprise Milestones (Recommended)
1. Enforce branch protection rules on `main`:
   - Require CI and Security checks
   - Require signed commits
   - Require code review approvals
2. Add OpenTelemetry traces and metrics export (OTLP).
3. Add secrets scanning in CI (gitleaks or GitHub Advanced Security if available).
4. Add SBOM generation and signed release artifacts (SLSA provenance + cosign).
5. Define RTO/RPO, backup strategy, and disaster-recovery runbooks.
6. Introduce deployment environments (dev/stage/prod) with protected secrets.

## Validation Checklist
Run these commands before production promotion:

```bash
cd backend
npm ci
npm run typecheck
npm run test:coverage
npm audit --audit-level=high

cd ../frontend
npm ci
npm run typecheck
npm run test:e2e
npm audit --audit-level=high
```
