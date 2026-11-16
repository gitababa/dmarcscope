# Changelog

Versions follow [semantic versioning](https://semver.org). The web app and the ingest worker
share one version number (`package.json` and `ingestor/__init__.py`).

Upgrading: deploy the new images, then run the migration command
(`node scripts/migrate.mjs`) before the new web version starts.

## 1.1.0

Hardening and fixes from a full code review. **Read "Changed" before upgrading.**

### Changed (may need action)

- OIDC sign-in is refused unless the provider sends `email_verified: true` for the `email`
  claim. There is no automatic fallback to `preferred_username` / `upn` any more: for
  Microsoft Entra ID set `OIDC_EMAIL_CLAIM=preferred_username`.
- `SESSION_MAX_AGE_HOURS` is capped at 168 (7 days) instead of 720.
- Docker Compose publishes the dashboard on `127.0.0.1:3000` only. Use `WEB_BIND` /
  `WEB_PORT` to change that; `PORT` in `.env` no longer affects Compose.
- `python -m ingestor import` exits 1 when a file could not be loaded or none was found.
- Migration `0002` adds two computed columns to `records` (one table rewrite) and
  `ingest_runs.failed`.
- Reverse-DNS names are stored only when forward-confirmed (the name resolves back to the
  IP). Sources whose PTR record does not match are shown by IP.
- `/api/cron/dns-check` answers 500 when every domain failed.
- Configuration errors are shown in full only in the server log, not to visitors.
- Database pool default is 10 connections (was 5), with a 30-second client-side query
  timeout (`DATABASE_QUERY_TIMEOUT_MS`).

### Added

- `OIDC_REQUIRED_CLAIMS` — pin sign-in to an organization on a shared provider
  (`hd=example.com` for Google Workspace, `tid=…` for Entra).
- `SESSION_NOT_BEFORE` — reject sessions issued before a given moment.
- `GET /api/cron/status` — ingest health for monitors (503 when no run has completed within
  `INGEST_STALE_HOURS`), a warning banner on the overview, and a "failed" run status.
- `DATABASE_STATEMENT_TIMEOUT_MS`, `INGEST_STALE_HOURS`.
- CI: typecheck, tests, build, end-to-end sign-in, image builds and the README quick start.

### Fixed

- A DNS timeout during a check was stored as "no SPF record" / "not in SPF", which made the
  Issues page call legitimate senders unauthorized. Such results are now marked incomplete.
- A malformed `ip4:` / `ip6:` range anywhere in an SPF include tree crashed the Issues page.
- A lost database connection left the ingest run open, hid the real error and blocked the
  next run. The run now stops at once and is recorded as failed.
- SIGTERM closes the ingest run instead of leaving it "in progress".
- Two ingest runs started at the same instant could both proceed.
- A reverse-DNS lookup stuck in the resolver could delay the worker's exit.
- The README quick start returned HTTP 500; the Kubernetes example could not start with
  `runAsNonRoot` (images now use numeric users).
- Daily volume bars depended on the database session's time zone.
- SPF: `a/NN` prefixes were applied to IPv6 addresses; `redirect=` was followed in records
  with an `all` mechanism; `ptr` and `exists` were not counted toward the 10-lookup limit.
- The login-state cookie was not cleared over https.
- Redirects to the login page could point at the container's own address behind a reverse
  proxy; they now use `APP_URL`.

### Security

- Names taken from reports (DKIM selectors and signing domains) are validated before being
  used in DNS queries; SPF expansion has a total time budget.
- One report can write at most 50,000 records, 20 DKIM/SPF results per record, and flat,
  length-limited JSON.
- `proxy-jwt` assertions must carry an expiry and a single well-formed address.
- The worker warns on every run while `ALLOWED_DOMAINS` is unset.

## 1.0.0

Initial public release.
