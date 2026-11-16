# Changelog

Versions follow [semantic versioning](https://semver.org). The web app and the ingest worker
share one version number (`package.json` and `ingestor/__init__.py`).

Upgrading: deploy the new images, then run the migration command
(`node scripts/migrate.mjs`) before the new web version starts.

## 2.0.0 (unreleased)

2.0 moves configuration into the browser: after deploying with `DATABASE_URL`, `APP_URL` and
`APP_SECRET`, an administrator sets up everything else in the app. It is being built in
milestones (`docs/plan-2.0.md`); this section grows with each one.

**Upgrading from 1.1.x:** run the migrations and deploy; nothing in the environment has to
change, and a 1.1.x deployment behaves as before. See "From 1.1.x to 2.0" in
[docs/deployment.md](docs/deployment.md).

### Added — milestone 1, foundation

- Sign-in managed in the app when `AUTH_PROVIDER` is unset. With no owner yet the app serves only
  a setup wizard (`/setup`), unlocked by a one-time token printed to the log (or `SETUP_TOKEN`).
  It creates the owner account: password (scrypt) plus an authenticator app (TOTP), with ten
  one-time recovery codes. `/setup` is gone once an owner exists.
- Owner password sign-in, also on `oidc` deployments ("Owner sign-in" on the sign-in page), with
  per-account and per-address lockout that does not reveal whether an account exists.
- Roles `owner`, `admin`, `viewer`, read from the database on every request. Everyone who signs in
  is recorded; someone no rule admits becomes a pending request. Disabling a user, changing their
  role or setting `sessions_valid_after` applies on their next request.
- Access rules in the database (email domain or group → role), next to the environment lists,
  which keep working unchanged. `npm run settings:import` copies the lists into the database.
- Settings store: environment variable, else the value saved in the panel, else the default;
  validated, cached per instance for `SETTINGS_CACHE_SECONDS` and picked up by every instance
  without a restart. First settings: application name, ingest staleness, session length and the
  machine endpoint token (`APP_NAME`, `INGEST_STALE_HOURS`, `SESSION_MAX_AGE_HOURS`,
  `CRON_SECRET`).
- Secrets saved in the database are encrypted (AES-256-GCM, keys derived from `APP_SECRET`), in a
  format the ingest worker reads too. `APP_SECRET_PREVIOUS` and `npm run secrets:reencrypt` rotate
  `APP_SECRET`.
- Audit log in the database (append-only; the database refuses changes), shown under
  **Admin → Audit log**. The JSON audit lines on stdout stay.
- A minimal **Admin** area: settings with where each value comes from, users, audit log.
- `APP_SECRET`, `APP_SECRET_PREVIOUS`, `SETUP_TOKEN`, `SETTINGS_CACHE_SECONDS`,
  `CLIENT_IP_HEADER`.

### Changed

- `AUTH_PROVIDER` is optional: unset now means "sign-in managed in the app" instead of a
  configuration error.
- `SESSION_SECRET` is optional when `APP_SECRET` is set. Where it is set it is used exactly as
  before, so upgrading signs nobody out.
- The request gate reads the user's role from the database (one indexed query per request). If
  the database cannot be reached, pages and `/api` answer 503 instead of letting anyone in.
  `/api/healthz` still needs no database.
- A non-numeric `INGEST_STALE_HOURS` or `SESSION_MAX_AGE_HOURS` is reported as an error (in the
  log and on the settings page) instead of silently becoming the default; out-of-range numbers
  are still clamped as before.
- With `AUTH_PROVIDER=none` every visitor has the owner role (previously admin).
- The ingest worker needs `cryptography` (pinned in `requirements.txt`).

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
