# Contributing

Issues and pull requests are welcome.

## Getting set up

See the Development section of the [README](README.md). In short: Node.js 20.9+, Python 3.11+
and a PostgreSQL database you can throw away.

## Before opening a pull request

```bash
npm run typecheck
TEST_DATABASE_URL=postgresql://... npm test
TEST_DATABASE_URL=postgresql://... .venv/bin/python -m pytest ingestor
```

CI runs the same checks, plus the end-to-end sign-in tests and container builds.

## Layout

| Path | What lives there |
|---|---|
| `app/` | Next.js routes: dashboard pages, sign-in, `/api` endpoints |
| `components/` | Shared UI components |
| `lib/` | Queries, DNS/SPF checks, diagnosis logic, authentication |
| `lib/auth/` | Sign-in providers, sessions, local accounts, authorization (`access.ts` is the one authorization function) |
| `lib/settings/` | Settings registry and store (environment → database → default) |
| `lib/envelope.mjs`, `ingestor/crypto.py` | The encrypted-secret format, shared by both runtimes |
| `proxy.ts` | Request gate: authentication and Content-Security-Policy |
| `ingestor/` | Python ingest worker and its tests |
| `db/migrations/` | SQL migrations, applied in filename order |
| `tests/` | TypeScript unit, database and end-to-end tests |
| `tests/vectors/` | Test vectors both test suites read (keep them in sync) |

## Guidelines

- Schema changes go in a new numbered file in `db/migrations/`; never edit one that has shipped.
  A column both the web app and the worker use is a contract: change both sides and both test
  suites together.
- Every query in `lib/queries.ts` takes the `DomainScope` from `lib/auth/access.ts`; pages get it
  only from `requireViewer()`.
- New configuration needs an entry in `.env.example` and `docs/configuration.md`.
- Behaviour changes need a test. Security-relevant code (anything under `lib/auth/`, `proxy.ts`,
  the `/api` routes) needs one that covers the rejection path, not just the happy path.
- The UI must keep working with no third-party network requests.
- User-visible changes get a line in `CHANGELOG.md`. The version lives in `package.json` and
  `ingestor/__init__.py`; a test checks that they agree.

By contributing you agree that your contributions are licensed under the Apache License 2.0.
