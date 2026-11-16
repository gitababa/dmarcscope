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
| `lib/auth/` | Sign-in providers, sessions, authorization |
| `proxy.ts` | Request gate: authentication and Content-Security-Policy |
| `ingestor/` | Python ingest worker and its tests |
| `db/migrations/` | SQL migrations, applied in filename order |
| `tests/` | TypeScript unit, database and end-to-end tests |

## Guidelines

- Schema changes go in a new numbered file in `db/migrations/`; never edit one that has shipped.
- New configuration needs an entry in `.env.example` and `docs/configuration.md`.
- Behaviour changes need a test. Security-relevant code (anything under `lib/auth/`, `proxy.ts`,
  the `/api` routes) needs one that covers the rejection path, not just the happy path.
- The UI must keep working with no third-party network requests.
- User-visible changes get a line in `CHANGELOG.md`. The version lives in `package.json` and
  `ingestor/__init__.py`; a test checks that they agree.

By contributing you agree that your contributions are licensed under the Apache License 2.0.
