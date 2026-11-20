# Changelog

Versions follow [semantic versioning](https://semver.org). The web app and the ingest worker
share one version number (`package.json` and `ingestor/__init__.py`).

Upgrading: deploy the new images, then run the migration command
(`node scripts/migrate.mjs`) before the new web version starts.

## Unreleased

### Added — Deploy with Vercel

- A **Deploy with Vercel** button in the README: it copies the repository into the deployer's
  own GitHub account, creates a Neon database, asks for `APP_SECRET` and `CRON_SECRET`, and
  deploys; the first build creates the tables.
- On Vercel, `APP_URL` is optional: without it the app uses the project's production address
  (`VERCEL_PROJECT_PRODUCTION_URL`, set by Vercel). `APP_URL` still wins when set.

### Changed — Vercel applies migrations itself

- Production builds on Vercel now apply pending migrations before the new version goes live
  (`scripts/vercel-build.mjs`, set as `buildCommand` in `vercel.json`). Preview builds never
  touch the database. A failed migration fails the build, and the previous deployment keeps
  serving. `MIGRATE_ON_BUILD=0` turns it off. Before this, upgrading without running
  `npm run db:migrate` broke the pages that use new tables.

### Added — deployment guide

- **Deployment guide** in the app (sidebar, for administrators, and on the setup page; it also
  opens once right after setup). Pick Vercel (Hobby or Pro), Docker Compose, Kubernetes or
  Google Cloud Run for the steps, and enter your report emails per day for recommended
  resources, schedules, time budgets and retention. The numbers come from measurements
  (`scripts/sizing_benchmark.py`: about 4 KB of database per report).
- `python -m ingestor pass`: one bounded pass for schedulers without a long-running process
  (Cloud Run jobs, ECS scheduled tasks). Mailboxes set up in the app are now read on Google
  Cloud too; docs/deployment.md is updated.

### Added — mailboxes on Vercel, and domains found in reports

- **Mailboxes set up in the app now work on Vercel**, on every plan. Each call of the ingest
  function is one bounded pass that reads the mailboxes that are due. **Test connection**
  answers within seconds and **Run now** starts at once: the app calls the function itself,
  signed with `APP_SECRET`. The daily cron reads panel mailboxes too. The Mailboxes page shows
  how often scheduled calls actually happen, and docs/deployment.md explains Hobby and Pro
  (more frequent schedules on Pro, or any outside scheduler).
- **Domains page**: every domain the reports were about, grouped under its registrable domain,
  with a **Monitor** button. Reports about domains nobody monitors are held for 14 days
  (bounded in size) and imported when you monitor the domain.
- A panel mailbox can be read before any domain is monitored: it stores nothing, lists the
  domains it finds and holds their reports. (It used to refuse to run.)
- Migration `0010`. Run the migration command when upgrading.

### Fixed — privacy

- The run history no longer keeps the subject line of messages that are not reports
  (parsedmarc names a message by its subject in its errors). Migration `0009` removes subjects
  already stored. Run the migration command when upgrading.

### Added — DNS checks

- **MTA-STS, TLS-RPT and BIMI** on the domain page. MTA-STS fetches the policy file (HTTPS, no
  redirects, verified certificate, private addresses refused) and checks that its `mx:` patterns
  cover every MX host. Not publishing one of these shows as "Not published", not as a failure.
- **DNS servers setting** (`DNS_SERVERS`, or Admin → Settings → DNS, owner only): up to four
  resolvers, optional `:port`, used by DNS checks, SPF expansion and the worker's reverse DNS.
  Unset, the host's own resolver is used as before. Each check records which servers answered.

### Fixed — DNS checks

- A subdomain without its own `_dmarc` record now gets the policy of the closest parent domain
  (with `sp=` in force) instead of "No DMARC record".
- A DKIM selector whose lookup timed out or failed is shown as unknown, not as a missing key.
- Every query has its own timeout and a retry, instead of failing on one dropped packet.
- `v=spf10` or `v=DMARC10` no longer count as SPF or DMARC records.

### Changed — setup and documentation

- `.env.example` leaves `AUTH_PROVIDER` unset (sign-in managed in the app), the default for a
  real deployment. The five-minute demo turns sign-in off explicitly.
- Deployment guide: a "First start" section (the setup token on each platform), a step-by-step
  Vercel guide, Docker Compose with the mailbox worker by default, and Kubernetes manifests for
  2.0 including the worker.

### Changed — interface redesign

- A new interface: a sidebar groups every page (Monitor; Data & alerting; Access; System), with
  badges for pending access requests and open alert events, the ingest status, the signed-in
  user and a light / dark / automatic theme switch (kept in a `theme` cookie, so the first paint
  is already right). On narrow screens the sidebar becomes a drawer.
- New design system in `app/globals.css` and `components/ui.tsx`: one set of colour tokens for
  both themes (`light-dark()`), cards, stat tiles, rings, donuts and inline icons. Still no
  external fonts, scripts or images.
- Administration pages have their own titles instead of a shared "Administration" header and tab
  row. Admin → Mail is now **Mailboxes**, Admin → Domains **Monitored domains**, Admin → Users
  **People** and API access **API & SCIM**; the URLs are unchanged.
- Settings are grouped (General, Data & retention, Sign-in & access, Email delivery, Alerts &
  automation). Alerts are split into tabs: Events, Rules, Channels and Delivery history.

### Added

- **Setup token, easier to find:** `/setup` says when the newest token was written to the log,
  where to find it on each platform, and has a **Write a new token to the log** button for when
  the line is gone (a platform keeping an hour of logs). The token is still never shown on the
  page; earlier tokens keep working, at most five are usable at once, and one can be requested
  per minute.
- **Vercel:** the Mailboxes page explains that Vercel reads the mailbox from the `IMAP_*`
  variables, and which one is set.
- A **health score** (0–100, graded A–F) per domain and, weighted by volume, for all of them:
  authentication rate (50), published policy (30) and DKIM coverage (20), minus 10 for each
  failing DMARC or SPF check. Every page that shows it also shows how it was made up
  (`lib/health.ts`).
- **Domains** (`/domains`): a card per domain with its grade, policy, compliance, a volume trend
  and the latest DNS check, sortable by health, volume or name.
- **Sources** (`/sources`): every sending source across domains (or one domain), with the sender
  mix by category; selecting a category filters the list.
- Overview: a security-posture summary, a "Needs attention" list (weakest domains and the top
  failing sources) and the daily compliance rate drawn over the volume chart.
- Issues: totals per diagnosis (unauthorized, needs a fix, benign) and a filter by kind.
- Domain page: health breakdown, an alignment donut and a card per DNS record.

## 2.0.0 (2026-11-19)

2.0 moves configuration into the browser: after deploying with `DATABASE_URL`, `APP_URL` and
`APP_SECRET`, an administrator sets up everything else in the app. The design and the decisions
behind it are in the `docs/` guides; the sections below list what each part added.

**Upgrading from 1.1.x:** run the migrations and deploy; nothing in the environment has to
change, and a 1.1.x deployment behaves as before. See "From 1.1.x to 2.0" in
[docs/deployment.md](docs/deployment.md).

### Added — foundation

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

### Added — people

- **Admin → Users**: pending requests (approve with a role, or reject), search and filters,
  invitations, and per person: change role, disable and enable, sign out everywhere, remove.
- **Admin → Access rules**: add and delete email-domain and group rules; the environment's rules
  are shown read-only.
- **Admin → Audit log**: filters (action, who, target, dates) and CSV download.
- Guard rails: an admin cannot change an owner or grant a role above their own; nobody can
  disable or remove themselves; the last active owner cannot be demoted, disabled or removed.
  Every change and every refusal is audited.
- Migration `0004` (invitations, audit log indexes).

### Added — single sign-on in the panel

- **Admin → Sign-in** (owner): an OpenID Connect connection from a preset (Google, Microsoft
  Entra ID, Okta, or any other provider). A draft is tested with a real sign-in in a new
  window, which shows the claims that came back and which rule would admit that person. Only a
  passed test of the draft as saved, less than a day old, can activate it. Walkthroughs per
  provider in [docs/sso.md](docs/sso.md).
- Switches: password sign-in for non-owners (`AUTH_LOCAL_SIGNIN_NON_OWNERS`), require single
  sign-on (`AUTH_ENFORCE_SSO`). The owner's password sign-in is never affected.
- Migration `0005` (`sso_connections`).

### Added — mail and domains

- **Admin → Mail**: reports mailboxes set up in the browser: IMAP with a password, Microsoft 365
  (an app registration with `IMAP.AccessAsApp`, client credentials) and Google Workspace (a
  service account with domain-wide delegation), both over `XOAUTH2`. **Test connection**, **Run
  now**, pause, and each mailbox's run history with its problems. Step by step in
  [docs/mail.md](docs/mail.md). The Microsoft 365 and Google paths are **unverified** against
  real tenants so far.
- **Admin → Domains**: the monitored domains, replacing `ALLOWED_DOMAINS` (which still wins when
  set). A mailbox set up in the browser reads nothing until a domain is listed.
- Retention in the panel (`ingest.retention_days`, or `RETENTION_DAYS` as before).
- `python -m ingestor serve`: a long-running worker that reads the panel's mailboxes on their
  schedules and carries out the panel's requests. Any number may run (one run per mailbox at a
  time); a killed worker's run is closed as failed by the next one; `SIGTERM` stops after the
  current message. Docker Compose: `docker compose --profile serve up -d`.
- Migration `0006` (`mailboxes`, `monitored_domains`, `worker_jobs`, `worker_heartbeats`;
  `ingest_runs.mailbox_id` and `trigger`).

### Added — alerting

- **Admin → Alerts:** rules for a new source failing DMARC above a volume threshold, compliance
  for a domain dropping below a threshold, ingest going stale, and a published DMARC or SPF record
  changing. Channels: email (SMTP settings in Admin → Settings, owner-only; TLS always, certificate
  always verified), a signed webhook (HMAC-SHA256 over `timestamp.body`) and Slack-compatible
  webhooks. See [docs/alerts.md](docs/alerts.md).
- Deduplication (one open event per condition, enforced by a unique index), quiet periods with up
  to three reminders, optional "cleared" notices, a **Send test** button and a delivery history
  with retries (1, 5, 30 minutes) and short errors.
- Evaluated every five minutes by the web app where it runs as a long-running process, and by
  `GET|POST /api/cron/alerts` (bearer token) on serverless deployments; one evaluation at a time
  across replicas.
- Webhook addresses and signing secrets are stored encrypted (purpose `alert`) and never shown
  again; `secrets:reencrypt` covers them. Outbound requests refuse private, loopback and
  link-local destinations, redirects and non-https addresses unless the owner allows it, on every
  delivery, and connect to the address they validated.
- DNS checks now record `lookup_failed` for a DMARC or SPF lookup that timed out, so a timeout is
  never mistaken for a record that was removed.
- Upgrading: run the migrations (`0007`). With no rules nothing
  changes and nothing is sent.

### Added — enterprise access

- **Per-domain permissions:** limit a viewer, directly or through a group, to chosen domains
  (Admin → Users, Admin → Groups). Every query in `lib/queries.ts` filters by the caller's scope, a
  test fails if one does not, and a domain outside the scope answers "not found". Administrators and
  owners always see everything. A limited setting with no domains sees nothing, and the new setting
  `access.domain_default` (`ACCESS_DOMAIN_DEFAULT`, `all` by default, `none` recommended once groups
  are limited) decides what a viewer with no scope sees, so a missing group claim cannot widen
  anyone's access. See [docs/enterprise.md](docs/enterprise.md).
- **SCIM 2.0** (`/scim/v2`): users and groups, behind a token only an owner creates. Provisioned
  people are viewers; SCIM cannot set roles, rename an e-mail address or touch an owner;
  deactivating (`active:false` or `DELETE`) takes effect on the person's next request. SCIM groups
  count for domain scopes only, never for access rules.
- **API tokens and a read-only JSON API** (`/api/v1`): scopes (`domains:read`, `reports:read`,
  `dns:read`), required expiry, domain limits, revocation, never wider than the creator; only the
  token's SHA-256 is stored and the token is shown once. `format=csv` and CSV downloads on the domain
  and Issues pages, with spreadsheet formulas neutralized.
- Migration `0008` (`domain_scopes`, `domain_grants`, `groups`, `group_members`, `api_tokens`,
  `users.external_id`). Upgrading changes nothing for anyone until an administrator uses a feature.

### Security

- Required claims (`OIDC_REQUIRED_CLAIMS`, and those of a panel connection) must be in the signed ID
  token; a value from the UserInfo endpoint no longer satisfies them.
- Mailbox passwords, client secrets and keys saved in the browser are encrypted for the worker
  only: the web app has no way to decrypt them. OAuth tokens are only ever sent to the
  provider's own IMAP server, and token endpoints are fixed in code (a key file's `token_uri` is
  ignored).
- `npm run secrets:reencrypt` now also re-encrypts the single sign-on client secret, which it
  previously missed, and mailbox secrets.

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
- `run`, `import` and `enrich` also use the monitored domains and retention saved in the panel
  when `ALLOWED_DOMAINS` / `RETENTION_DAYS` are not set.

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
