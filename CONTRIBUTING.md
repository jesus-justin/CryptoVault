# CONTRIBUTING.md

## Development prerequisites

- Node.js 20 LTS
- npm 10+
- Docker and Docker Compose

## Local setup

1. Copy [.env.example](.env.example) to `.env` and fill values.
2. Install dependencies:
   - `cd backend && npm ci`
   - `cd frontend && npm ci`
3. Run backend and frontend in separate terminals:
   - `cd backend && npm run dev`
   - `cd frontend && npm run dev`

## Contribution workflow

1. Create a feature branch from `develop`.
2. Keep changes scoped to one concern (API, frontend, docs, infra).
3. Add tests for any service/controller/route behavior change.
4. Run checks before opening PR:
   - `backend: npm run lint && npm run typecheck && npm test`
   - `frontend: npm run lint && npm run typecheck`
5. Open a PR with a clear summary and security impact notes.

## Adding a new cryptographic algorithm

1. Update algorithm registry in [backend/src/utils/algorithmMetadata.ts](backend/src/utils/algorithmMetadata.ts).
2. Add strict TypeScript types in [backend/src/types/crypto.types.ts](backend/src/types/crypto.types.ts).
3. Implement crypto logic in service layer only.
4. Add controller method and route schema validation.
5. Add OpenAPI documentation in route JSDoc.
6. Add unit and integration tests.
7. Surface status and warnings in frontend UI components.

## Security requirements for contributors

- Never use `Math.random()` for cryptographic operations.
- Never implement ECB mode.
- Never log plaintext, raw keys, passwords, or tokens.
- Use timing-safe comparison helpers for secret equality.
- Zero sensitive buffers after use.
- Keep API responses in standardized envelope format.

## Pull request checklist

- [ ] No TODO/placeholder code
- [ ] No `any` type usage
- [ ] New/updated tests included
- [ ] Lint and typecheck pass
- [ ] Security impact reviewed
