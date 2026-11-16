# DMARCscope 2.0 plan

Goal: after deploying with three environment variables, an administrator sets up and runs
everything from the browser — sign-in (SSO), the reports mailbox, monitored domains, users
and access, alerting. Today (1.1.0) all of that is environment variables and there is no
user record at all.

This file is the single source of truth for 2.0. When a decision changes, edit it here in
the same pull request.

## How to work

1. Work one milestone at a time, in order. A milestone is one pull request into the
   long-lived `2.0` branch (create it from `main` if it does not exist). `main` stays at
   the released 1.1.x line.
2. At the start of milestones 2–7, first replace that milestone's outline below with a
   concrete design (tables, routes, screens, failure cases) and commit it. Milestone 1 is
   already designed.
3. A milestone is done when every box in its "Done when" list is true and every item in
   "Definition of done" holds. Then open the pull request, report, and stop. The next
   milestone starts only when the user says so.
4. When something here turns out wrong or impossible, stop and say so with the evidence;
   do not quietly build something else.

## Definition of done (every milestone)

- `npm run typecheck`, `npm test`, `python -m pytest ingestor`, `npm run build`,
  `npm run test:e2e` and `npm audit --omit=dev --audit-level=high` pass locally, and the
  CI workflow is green on the pull request, including the Docker job.
- Every new rule that refuses something (authentication, authorization, validation, rate
  limit) has a test for the refusal, not only for the success path.
- Every new screen was opened in a browser and exercised, including its error states and
  at phone width.
- `docs/` and `.env.example` describe the new behaviour; `CHANGELOG.md` has the entry;
  the upgrade path from the previous version is written down and was actually run.
- New migrations are new numbered files; shipped ones are never edited.
- A security review of the diff was run and its findings fixed or listed in the pull
  request (use the `review-council` or `security-review` skill if available).

## Decisions already made

These were agreed with the owner. Build to them.

**Configuration**
- Required environment: `DATABASE_URL`, `APP_URL`, `APP_SECRET` (32+ random characters).
  Nothing else is required to reach the setup wizard.
- Every setting has one resolved value: environment variable if set, else database, else
  default. A setting supplied by environment is shown in the panel as "managed by
  environment" and cannot be edited there. This is what keeps every existing 1.1.0
  deployment working unchanged after upgrading, and keeps Git-managed deployments possible.
- Settings changes take effect without a restart on every replica (short per-process cache
  keyed on a version counter in the database).

**Secrets**
- Secrets in the database (OIDC client secret, mailbox credentials, webhook URLs, TOTP
  seeds) are encrypted with AES-256-GCM under a key derived from `APP_SECRET` with HKDF,
  one derived key per purpose. The same format must be readable from TypeScript and
  Python, because the worker reads mailbox credentials.
- A saved secret is never sent back to the browser; forms show "set" / "not set" and
  accept a replacement.
- `APP_SECRET` rotation is supported: `APP_SECRET_PREVIOUS` decrypts, and a command
  re-encrypts everything under the current key.
- `SESSION_SECRET` keeps working where set; without it the session key derives from
  `APP_SECRET`.

**Sign-in**
- No SAML unless milestone 7 is requested. OIDC only inside the app.
- One local "owner" account exists so the app is usable before SSO is configured and when
  SSO breaks. Password plus TOTP. Local sign-in for anyone else is off by default and can
  be turned off entirely for non-owners once SSO is verified.
- First run: with no owner in the database the app serves only the setup wizard, unlocked
  by a one-time setup token. The token is generated on first start, stored hashed, logged
  once, expires after 24 hours, and can instead be supplied as `SETUP_TOKEN`.
- An SSO connection becomes active only after an administrator completes a real sign-in
  with it from the "Test" button. Saving alone never changes how people sign in.
- Proxy sign-in (`proxy-jwt` for Google IAP / Cloudflare Access, `proxy-header`) is a
  property of the deployment and stays environment-only. In those modes the proxy supplies
  the identity and the database supplies the role. `AUTH_PROVIDER=none` stays a
  development-only mode.
- Roles: `owner` (everything, including sign-in and secret settings), `admin` (users,
  mailbox, domains, alerts, DNS checks), `viewer`. Per-domain scoping arrives in
  milestone 6; milestone 1 must not make it a rewrite (see data model).
- Deny by default everywhere. A person the identity provider authenticates but no rule
  admits becomes a pending request an admin can approve.
- Removing or disabling a user, or changing their role, takes effect on their next request.

**Worker**
- The worker gains a long-running mode (`python -m ingestor serve`) that reads mailbox
  connections and schedules from the database. The one-shot `run` / `import` / `enrich`
  commands, their JSON output and exit codes stay as documented in
  `docs/configuration.md`, and the Vercel adapter keeps working from environment settings.
- The web app never opens a mailbox connection itself. "Test connection" and "Run now"
  are requests the worker picks up from a jobs table, so mailbox credentials are only ever
  used from the worker's network position.

**Out of scope for 2.0**
Multi-tenancy (several organizations in one deployment), failure (RUF) reports, TLS-RPT,
a public sign-up flow.

## What you cannot learn by reading the code

- `proxy.ts` runs on the Node.js runtime, so it may query PostgreSQL. Today it does not;
  from milestone 1 the gate resolves roles from the database on every request. Keep that
  to one indexed query behind the settings/user cache, and keep `/api/healthz` free of
  database access.
- Two runtimes share one schema with no generated types: the Next.js app (`lib/`) and the
  Python worker (`ingestor/`). A column the worker writes or reads is a contract; change
  both sides and both test suites in the same commit.
- The 1.1.0 review found the project's recurring failure shape: a check that silently
  passes when its input is missing or malformed (an absent `email_verified`, an unparsable
  setting, a DNS timeout read as "no record"). Treat "missing", "malformed" and "could not
  find out" as their own outcomes, never as the permissive default.
- Report emails, and everything parsed out of them, are written by strangers. Any value
  from a report that reaches a DNS query, a log line, an alert message or the UI is
  untrusted input.
- This machine has no Docker. The Docker build, Compose and the README quick start are
  only exercised by the `images` job in CI, so a change to `Dockerfile*`,
  `docker-compose.yml` or the quick start is unverified until CI has run.
- Database tests need `TEST_DATABASE_URL` pointing at a disposable PostgreSQL; they create
  and drop their own schemas. Without it they are skipped, which looks like success. Make
  sure they actually ran.
- A repository hook refuses `git add -A` / `git add .`; stage files by name.
- The repository's configured commit identity is a GitHub no-reply address. Leave it as is
  and keep the owner's personal email out of commits, files and requests to outside
  services.
- A sibling folder, `../internal dmarcian tool`, is the pre-release project of the
  owner's former employer. Its `.env.local` and `.vercel/` hold that company's live
  credentials. Never read, copy or use them, and never connect to anything they point at.
- New dependencies: before adding one, open its upstream repository and confirm the
  package name and install command from there. Prefer what Node and Python already ship
  (`node:crypto` has scrypt, HKDF, AES-GCM and HMAC; TOTP is thirty lines over HMAC with
  published test vectors in RFC 6238). The worker will need `cryptography` for AES-GCM and
  HKDF; pin it in `requirements.txt` like the existing pins.

## Milestone 1 — Foundation

Everything later stands on this. It adds password handling, secret storage and a setup
flow, which are new attack surface, so it is the milestone to be slowest on.

### Data model (migration `0003`)

- `settings` — `key`, `value` (JSON), `is_secret`, `updated_at`, `updated_by`. Secret
  values hold the encrypted envelope. One extra row (or a sequence) is the version counter
  bumped on every write.
- `users` — `id`, `email` (unique, lower-case), `name`, `role`, `status`
  (`pending` / `active` / `disabled`), `source` (`local` / `oidc` / `proxy` / `scim`),
  `oidc_subject`, `password_hash`, `totp_secret` (encrypted), `totp_confirmed_at`,
  `failed_logins`, `locked_until`, `sessions_valid_after`, `last_login_at`, `created_at`,
  `created_by`.
- `access_rules` — `kind` (`email_domain` / `group`), `value`, `role`, `created_by`,
  `created_at`. Replaces `ALLOWED_EMAIL_DOMAINS`, `ALLOWED_GROUPS`, `ADMIN_GROUPS`.
- `recovery_codes` — hashed one-time codes for the owner's TOTP.
- `audit_log` — `at`, `actor_user_id`, `actor_email`, `action`, `target`, `detail` (JSON,
  never containing secret values), `ip`. Append-only: no update or delete path in the
  application.
- `setup_tokens` — hashed token, `expires_at`, `used_at`.
- Per-domain scoping is anticipated, not built: authorization goes through one function
  that returns the role and the set of visible domains (for now always "all"). No query in
  `lib/queries.ts` may be called from a page without passing through it. Milestone 6 then
  changes the function, not every page.

### Behaviour

1. **Settings store** (`lib/settings/`): typed registry of every setting (key, type,
   default, secret or not, environment variable name, validator). Reads resolve
   environment → database → default. Writes validate, encrypt secrets, bump the version,
   and write an audit entry. An invalid stored value is an error surfaced to admins, never
   silently replaced by the default.
2. **Encryption** (`lib/crypto.ts` and `ingestor/crypto.py`): one envelope format with a
   version byte and key identifier. A shared set of test vectors, checked into the
   repository, is decrypted by both test suites.
3. **Setup wizard** (`/setup`): reachable only while no owner exists, and only with the
   setup token. Creates the owner (password policy: 12+ characters, checked against a
   small built-in list of the most common passwords), enrols TOTP with a confirmation code,
   shows recovery codes once. After completion `/setup` returns 404 forever.
4. **Local sign-in**: password verified with scrypt (parameters stored in the hash string
   so they can be raised later), then TOTP. Failed attempts are counted per account and per
   client address in the database with exponential lockout; responses and timing do not
   reveal whether an account exists. Session cookie as today, plus the user id.
5. **Access from the database**: `authenticate()` turns the request into an identity as
   today, then resolves the user row: `disabled` → refused; session issued before
   `sessions_valid_after` → refused; known user → their role; unknown but admitted by an
   access rule → created `active` with the rule's role; otherwise created `pending` and
   refused. The environment lists (`ADMIN_EMAILS` and the rest) keep working as rules that
   cannot be edited in the panel.
6. **Audit log**: every sign-in, refusal, setting change, user change and setup step. The
   existing JSON audit lines on stdout stay.
7. **Import**: `npm run settings:import` (or a wizard step) copies the current
   environment's access lists into `users` / `access_rules`, idempotently, so an operator
   can then delete the variables.
8. **Minimal `/admin`**: just enough to prove the foundation — an owner can see resolved
   settings with their source (environment / database / default), see users, and read the
   audit log. Full management screens are milestone 2.

### Done when

- [ ] A fresh database plus the three required variables leads to `/setup`, and completing
      it yields a signed-in owner; this path is covered by an end-to-end test.
- [ ] An existing 1.1.0 deployment (its environment unchanged) upgrades by running the
      migration and behaves exactly as before: the 1.1.0 end-to-end tests pass unmodified.
- [ ] Tests show refusal for: wrong or expired or reused setup token; `/setup` after an
      owner exists; wrong password; wrong, reused and replayed TOTP codes; locked account;
      disabled user; session older than `sessions_valid_after`; a viewer or admin calling
      an owner-only action directly; a secret setting requested through any read path.
- [ ] A value encrypted by TypeScript decrypts in Python and the reverse, from shared
      vectors; decryption with the wrong key, a truncated envelope or a flipped bit fails
      loudly.
- [ ] Changing a setting in one process is visible in another within the cache window,
      demonstrated by a test with two pools.
- [ ] No secret value appears in any log line, audit entry, error message or HTML
      response (a test greps for seeded canary values).

## Milestone 2 — Admin panel: people

Users list with search and filters; invite by email (creates `pending`→`active` on first
sign-in); change role; disable and re-enable; "sign out everywhere"; approve or reject
pending requests. Access rules editor (email domains, IdP groups → role). Audit log viewer
with filters and CSV export.

Guard rails: the last owner cannot be removed, demoted or disabled; an admin cannot grant
a role above their own; every mutation is a server action that re-checks the caller's role
and writes an audit entry.

Done when: each action and each guard rail has a test for its refusal; the panel works
with keyboard only and at phone width; an admin who is demoted mid-session loses the panel
on their next request.

## Milestone 3 — Admin panel: SSO

OIDC connection form with presets (Google, Microsoft Entra ID, Okta, Keycloak, generic):
issuer, client id, client secret, scopes, email claim, groups claim, required claims,
button label. "Test" runs a real authorization-code flow in a new window against the
unsaved-as-active configuration and shows the claims that came back and which rule would
admit that person. Only a successful test can activate. Switches: allow local sign-in for
non-owners; enforce SSO.

Carry over every 1.1.0 rule from `lib/auth/oidc.ts` (verified email, no claim fallback,
required claims, https issuer). The owner's local sign-in always remains available.

Done when: a misconfigured connection (wrong secret, unreachable issuer, wrong redirect
URI) cannot be activated and cannot lock anyone out, shown by tests; switching providers
does not invalidate the owner's access; documentation has a walkthrough per preset.

## Milestone 4 — Admin panel: mail and domains

Mailbox connections: IMAP with password; Microsoft 365 and Google through OAuth. Start by
researching, from Microsoft's and Google's own documentation, which flow an unattended
service should use for a shared mailbox today, and record the choice and its sources in
this file before building. Test connection; schedule; run now; run history with per-message
errors; monitored-domain list (replacing `ALLOWED_DOMAINS`, and required before the first
ingest in a wizard-configured install); retention.

Worker: `serve` mode, the jobs table, graceful shutdown, one active run per mailbox,
leader safety when two workers run.

The owner must supply a real Microsoft 365 or Google tenant to verify OAuth against.
Whatever was not exercised against a real provider is labelled "unverified" in the pull
request and the documentation.

Done when: a wizard-configured install ingests from an IMAP mailbox with no mailbox
environment variables; credentials are never readable through the web app; killing the
worker mid-run leaves a closed, failed run and the next run proceeds; an environment-
configured 1.1.0 worker still runs unchanged.

## Milestone 5 — Alerting

Rules: a new source failing DMARC above a volume threshold; compliance for a domain
dropping below a threshold; ingest stale; a published DMARC / SPF record changed.
Channels: email (SMTP settings in the panel), generic webhook (signed), Slack-compatible
webhook. Deduplication, quiet periods, a test button, delivery history.

Alert text is built from report data: escape it for each channel, and never follow
redirects or call private addresses from a webhook unless an owner allows it.

## Milestone 6 — Enterprise access

Per-domain permissions (users or groups limited to chosen domains) through the single
authorization function from milestone 1, with a test that every query path is filtered.
SCIM 2.0 provisioning (users and groups; deactivation is immediate). API tokens with
scopes and expiry, a read-only JSON API, CSV export.

## Milestone 7 — SAML (only if requested)

Service-provider-initiated SAML 2.0 using a maintained, widely used library chosen after
checking its upstream advisories. Signed assertions required, audience and recipient
checked, replay cache, metadata import. Highest-risk piece of the plan; gets its own
security review.
