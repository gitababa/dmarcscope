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

### Decisions made while building milestone 1

Clarifications of the decisions above, made where two of them pulled in different directions or
the plan left a detail open. Each keeps the agreed behaviour.

- **`AUTH_PROVIDER` unset means "sign-in managed in the app"** (owner password + TOTP now, OIDC
  from the panel in milestone 3). The "only the setup wizard until an owner exists" rule applies
  in this mode only. A 1.1.0 deployment has `AUTH_PROVIDER` set and no owner, so applying the rule
  there would break "behaves exactly as before". On those deployments `/setup` is still available
  (with the token) to create an owner, but nothing is locked behind it.
- **Rule-admitted roles are re-evaluated on every request.** `users.role_source` (`assigned` /
  `rule`, a column not in the original list) records whether a role was given to the person or
  came from an access rule. The effective role is the higher of the assigned role and what the
  rules give now, so removing someone from `ADMIN_EMAILS` (or deleting a rule) still removes the
  access it gave, as in 1.1.0. A disabled row overrides everything.
- **Further schema details:** `users.totp_last_step` (makes each TOTP code single-use);
  `auth_throttle` (per-address counts, and per-address-typed counts for unknown accounts so a
  lockout does not reveal whether the account exists); `config_version` as a separate one-row
  table (bumped in the write's transaction, so a reader can never cache new data under an old
  version); `setup_tokens.expires_at` is NULL for a `SETUP_TOKEN`-supplied token. The audit log
  has no foreign key to `users` (so deleting a user never rewrites history) and a trigger refuses
  `UPDATE` and `DELETE`.
- **Envelope format:** version byte `0x01`, 4-byte key id (HKDF of `APP_SECRET`), 12-byte nonce,
  ciphertext and tag, base64url. Keys per purpose (`setting`, `totp`) via HKDF; the AAD binds the
  header, the purpose and the record (`cron.secret`, `user:42`). `lib/envelope.mjs` is plain
  JavaScript so the command-line scripts can use it without a build step.
- **Pre-sign-in forms are route handlers** (`/setup/*`, `/auth/password`,
  `/auth/second-factor`) with plain HTML forms, an `Origin` check and 303 redirects, so they work
  without JavaScript and can be driven by the end-to-end tests. Server actions remain the rule for
  signed-in mutations.
- **Registered settings in milestone 1** are only those something reads through the store:
  `app.name`, `ingest.stale_hours`, `session.max_age_hours`, `cron.secret` (owner-only, secret).
  Registering a setting nothing reads would show a control that does nothing.
- **Client address** for per-address limits and the audit log comes from `CLIENT_IP_HEADER`
  (default: last `X-Forwarded-For` entry), because Next.js keeps a client-sent `X-Forwarded-For`.
  Per-account lockout does not depend on it.
- **QR code:** `qrcode-generator` (MIT, no dependencies; checked upstream) renders the TOTP
  enrolment code server-side as an SVG path.

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

### Design

**Data model (migration `0004`).**
- `users.invited_at`, `users.invited_by`: an invitation is a `users` row with
  `status = 'pending'`, `role_source = 'assigned'`, the invited role, and `invited_at` set.
  A pending row without `invited_at` is a request (someone signed in and no rule admitted
  them).
- Indexes for the audit viewer's filters: `audit_log (action, id)`,
  `audit_log (lower(actor_email), id)`.
- No new status: rejecting a request sets `status = 'disabled'` (they stay refused, and an
  administrator can re-enable them later), and the audit log says it was a rejection.

**Who may do what.** Roles rank viewer < admin < owner. All of this needs admin or owner.
- An actor may change only a user whose role is at or below their own. An admin cannot touch
  an owner.
- An actor may grant only a role at or below their own. Only an owner can make an owner.
- Nobody can disable or remove themselves. Signing yourself out everywhere is allowed.
- The last active owner cannot be demoted, disabled or removed. "Last" is decided inside the
  transaction, with the owner rows locked (`FOR UPDATE`), so two owners demoting each other at
  once cannot leave none.
- The same rank rules apply to access rules: an admin can add rules for admin or viewer.
  Rules never grant owner (as in milestone 1).

**Sign-in for invited and approved people.** At the next request after an invitation,
`resolveAccess` finds the pending, invited row, makes it `active`, and records
`invitation_accepted`. Approving a request sets the chosen role (`assigned`) and makes the
row active. Both take effect on that person's next request. Invitations only matter for
people who sign in through SSO or a proxy. No email is sent: "invite" pre-approves an
address, and there is no mail delivery until milestone 5.

**Actions** (server actions; each re-checks the caller's role, runs in one transaction with
the target row locked, writes an audit entry, and writes an audit entry for a refusal too).
`lib/people.ts` holds the logic, so it can be tested against the database without Next.js.

| Action | Effect | Refused when |
|---|---|---|
| invite | new pending row with role, `invited_at` | address invalid or already known; role above caller |
| approve | pending request → active, chosen role | not a pending request; role above caller |
| reject | pending request → disabled | not pending |
| change role | role, `role_source = 'assigned'` | target above caller; role above caller; last owner |
| disable / enable | status | target above caller; self (disable); last owner (disable) |
| sign out everywhere | `sessions_valid_after = now()` | target above caller |
| remove | delete the row (history stays in the audit log) | target above caller; self; last owner |
| add rule / delete rule | `access_rules` (+ `config_version` bump) | invalid value; duplicate; role above caller |

**Screens** (all admin-only; plain forms that work without JavaScript and with the keyboard
alone; usable at 375px):
- `/admin/users`: pending requests first (approve with a role, or reject); then everyone,
  with search (address or name), filters (status, role, sign-in source) and pages of 50; an
  invite form.
- `/admin/users/[id]`: one person: role, status, source, last sign-in, invited by, lockout.
  Change role, disable or enable, sign out everywhere, remove (with a confirmation step).
  Only the actions the caller may take are shown. The server checks again anyway.
- `/admin/rules`: database rules (add, delete) and, read-only, the rules that come from the
  environment.
- `/admin/audit`: filters (action, actor, target, from/to date), pages, and "Download CSV"
  (`GET /admin/audit/export` with the same filters). The export is admin-only, capped at
  100,000 rows, and recorded in the audit log. Cells that a spreadsheet would read as a
  formula (`=`, `+`, `-`, `@`, tab, CR) are prefixed with `'`, because the audit log holds text
  strangers typed.

**Failure cases.** A user changed between page load and submit (role, status, deleted) is
re-read inside the transaction, so the decision is made on current data. The panel then
reports "changed meanwhile, see the current state". A demoted admin's next request has the
lower role (no cache), so the panel is gone. Search input is bound as a parameter, and
`%`/`_` are escaped for `ILIKE`.

**Built as designed**, plus:
- An admin cannot delete a rule that grants a role above their own. Rules grant only admin and
  viewer, so in practice this never refuses anyone today.
- Every action re-reads the caller's own account inside its transaction. If it was disabled or
  removed since the request started, the action is refused.
- Approve and reject also apply the rank rule: a request an owner raised to owner is not an
  admin's to decide. Enabling a user makes their role `assigned`, so a re-enabled rejected
  request actually gets in. An invitation lets someone in only if accepting it succeeded;
  otherwise the current row decides.
- On a confirmation step, keyboard focus moves to the confirming button. This is a small client
  component, because React does not apply `autoFocus` to server-rendered HTML.

## Milestone 3 — Admin panel: SSO

OIDC connection form with presets (Google, Microsoft Entra ID, Okta, generic; no Keycloak
preset, by the owner's decision during milestone 3; Keycloak works through the generic preset):
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

### Design

**Where it applies.** The panel manages SSO only when sign-in is managed in the app
(`AUTH_PROVIDER` unset). With `AUTH_PROVIDER=oidc`, the `OIDC_*` variables define the connection:
the SSO page shows it as "managed by environment" and offers no edits. Proxy modes have no SSO
page.

**Data model (migration `0005`).** Table `sso_connections`:
- `state`: `draft` or `active` (or `retired`). At most one row in each of `draft` and `active`,
  enforced by partial unique indexes.
- The connection itself: `preset`, `issuer`, `client_id`, `client_secret` (an encrypted
  envelope bound to the row, or NULL for a public client), `scopes`, `email_claim`,
  `groups_claim`, `required_claims`, `button_label`.
- `revision`: incremented on every save of the draft.
- `last_test` (JSONB): ok or failed, when, by whom, the revision it tested, the error code, the
  claims that came back (minus tokens), and which rule would admit that person.
- Audit columns.

The active connection is part of the cached settings snapshot, so every instance picks up an
activation within `SETTINGS_CACHE_SECONDS`.

**Lifecycle (owner only).**
1. *Edit*: there is one draft. Starting an edit copies the active connection into a new draft;
   the secret is decrypted and re-encrypted for the new row. Saving validates the form and bumps
   `revision`. A saved draft changes nothing about how anyone signs in.
2. *Test*: opens in a new window. `/auth/sso-test` runs the real authorization-code flow (PKCE,
   state, nonce) against the draft, and comes back to the same `/auth/callback`. The login-state
   cookie marks the attempt as a test and carries the draft id, the revision and the owner's id.
   A test callback never issues or changes a session and never creates users. It only records
   `last_test`, and only if the caller is still that same owner. Every 1.1.0 rule applies:
   verified email, the email from exactly one claim, required claims, https issuer.
3. *Activate*: allowed only when `last_test` succeeded **for the current revision** within the
   last 24 hours. In one transaction the previous active connection is retired, the draft becomes
   active, `config_version` is bumped, and an audit entry is written.
4. *Deactivate*: retires the active connection. Sign-in falls back to the owner's password.

**Switches** (registry settings, owner-only, environment-overridable):
- `auth.local_signin_non_owners` (`AUTH_LOCAL_SIGNIN_NON_OWNERS`, default off). Lets non-owners
  who have a password and TOTP (in practice: a former owner) use the password sign-in.
- `auth.enforce_sso` (`AUTH_ENFORCE_SSO`, default off). Non-owners must use SSO; the sign-in page
  hides the password form behind "Owner sign-in". It applies only while a connection is active,
  so it can never leave people with no way in.

**Never locked out.**
- The owner's password + TOTP sign-in is always available, whatever the switches or the state of
  the connection.
- A connection that breaks after activation (provider down, secret rotated) only makes the SSO
  button fail with an error; the owner signs in locally and fixes or deactivates it.
- Activating or switching a connection does not touch sessions or `users`, so the owner's (and
  everyone's) access is unchanged.

**Sign-in with the active connection.** The sign-in page shows the button (`button_label`).
`/auth/login` and `/auth/callback` use the active connection from the snapshot. The callback
resolves the person exactly as in milestone 1 (rules, pending requests, invitations), records
them as `source = 'oidc'`, and always puts their user id in the session cookie.

**Failure cases, all tested.**
- An unreachable issuer, or a discovery document whose issuer does not match: the test fails at
  the start.
- A wrong client secret: the token request is refused.
- A wrong redirect URI: the provider refuses, or returns an error to the callback.
- An unverified email, a missing email claim, a required claim that does not match.
- A test for an older revision, or one that is too old: activation is refused.
- A test callback presented with a different session, or with no session: no result is
  recorded.

**Presets** fill in the issuer pattern and claims, with notes:
- Google: `email`, `hd` recommended.
- Microsoft Entra ID: `preferred_username`, groups are object IDs, single-tenant issuer.
- Okta: `email`, `groups`.
- Generic.

`docs/sso.md` has a walkthrough per preset.

**Built as designed, plus:**
- The test is started by a same-origin form post (`POST /auth/sso-test`), so another site cannot
  make the owner's browser start one.
- Admins see only whether the draft passed; the details are the owner's.
- Required claims must come from the signed ID token. A value from UserInfo no longer counts;
  this applies to environment connections too.
- The presets' placeholders are refused, including Google's `hd=example.com`.
- No Keycloak preset, by the owner's decision; Keycloak works through the generic preset.

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

### Research: unattended access to a shared mailbox (done before building)

**Microsoft 365.** Use the OAuth 2.0 **client-credentials grant** with the **`IMAP.AccessAsApp`**
application permission of *Office 365 Exchange Online*. Setup:
1. Grant tenant admin consent.
2. Register the app's service principal in Exchange with `New-ServicePrincipal`.
3. Allow it into the reports mailbox, and only that mailbox, with
   `Add-MailboxPermission -AccessRights FullAccess`.

The token is requested with scope `https://outlook.office365.com/.default`. IMAP authenticates with
SASL `XOAUTH2` (`user=<mailbox>^Aauth=Bearer <token>^A^A`), naming the shared mailbox as the user.
Chosen over Microsoft Graph `Mail.Read` because Graph's application permission is tenant-wide
until narrowed by RBAC for Applications (Application Access Policies are legacy), whereas
mailbox permissions scope IMAP access to one mailbox by construction. Client secrets last at most
24 months (Microsoft recommends under 12), so the panel shows the secret's age.
Sources:
- [Authenticate an IMAP, POP or SMTP connection using OAuth](https://learn.microsoft.com/en-us/exchange/client-developer/legacy-protocols/how-to-authenticate-an-imap-pop-smtp-application-by-using-oauth)
- [Role Based Access Control for Applications in Exchange Online](https://learn.microsoft.com/en-us/exchange/permissions-exo/application-rbac)
- [Application Access Policies (legacy)](https://learn.microsoft.com/en-us/exchange/permissions-exo/application-access-policies)
- [Add and manage app credentials](https://learn.microsoft.com/en-us/entra/identity-platform/how-to-add-credentials)

**Google Workspace.** Use a **service account with domain-wide delegation**. A Workspace super
admin authorizes its client ID for the scope `https://mail.google.com/` in the Admin console. The
worker signs an RS256 JWT:
- `iss` = the service account,
- `sub` = the reports mailbox,
- `aud` = `https://oauth2.googleapis.com/token`,
- `exp` at most one hour after `iat`.

It exchanges the JWT with the `urn:ietf:params:oauth:grant-type:jwt-bearer` grant and logs in to
IMAP with `XOAUTH2`. Domain-wide delegation lets the key act as *any* user of the domain for that
scope, so the documentation asks for a dedicated service account used only here, with no other
scopes, and treats the key as the most sensitive secret in the deployment. (The narrower
`gmail.imap_admin` scope is for admin access and is not needed.) The JWT is signed with
`cryptography`, which the worker already depends on, rather than adding Google's client
libraries; the token exchange is tested against a mock endpoint that verifies the signature.
Sources:
- [Using OAuth 2.0 for Server to Server Applications](https://developers.google.com/identity/protocols/oauth2/service-account)
- [IMAP, POP, and SMTP: OAuth 2.0 mechanism (XOAUTH2)](https://developers.google.com/workspace/gmail/imap/xoauth2-protocol)

**Not verified without a real tenant.** Everything above is tested against local stand-ins
(a TLS IMAP server and token endpoints). Until the owner provides a Microsoft 365 and a Google
Workspace tenant, both providers are labelled *unverified* in the pull request and in
`docs/mail.md`.

### Design

**Data model (migration `0006`).**
- `mailboxes`:
  - `kind`: `imap` (password), `microsoft` or `google`;
  - `name`, `enabled`;
  - connection details: `host`, `port`, `security`, `username`, `folder`, `processed_folder`,
    `invalid_folder`;
  - provider IDs: `tenant_id`, `client_id`;
  - `secret`: the password, client secret or service-account key as an encrypted envelope,
    purpose `mailbox`, bound to the row;
  - `secret_updated_at`;
  - `interval_minutes` (15 to 1440, default 60);
  - audit columns.
- `monitored_domains (name, created_by, created_at)`. This replaces `ALLOWED_DOMAINS`, which,
  when set, still wins and makes the list read-only.
- `ingest_runs` gains `mailbox_id` (NULL for environment-configured runs and imports) and
  `trigger` (`schedule`, `manual`, `environment`).
- `worker_jobs`:
  - `kind`: `test` or `run`;
  - `mailbox_id`;
  - `status`: `queued`, `running`, `done`, `failed`;
  - `requested_by`, `requested_at`, `claimed_by`, `claimed_at`, `finished_at`;
  - `result` (JSONB: a short outcome and message, never a secret).
- `worker_heartbeats (worker_id, hostname, version, started_at, seen_at)`, so the panel can say
  whether a worker is running.
- Setting `ingest.retention_days` (`RETENTION_DAYS`), read by the worker with the same
  resolution: environment, then database, then default.

**Credentials are never readable through the web app.** The web app encrypts mailbox secrets
and stores them; it has no code path that decrypts purpose `mailbox` (a test asserts it). Forms
show "set" or "not set" and take a replacement. Only the worker decrypts, from its own network
position, as the plan requires.

**Worker `serve` mode** (`python -m ingestor serve`):
- **Loop:** every few seconds it writes a heartbeat, claims queued jobs
  (`FOR UPDATE SKIP LOCKED`), and runs every enabled mailbox whose interval has passed since its
  last scheduled run.
- **One active run per mailbox:** a run holds a PostgreSQL session advisory lock for that mailbox
  (`pg_try_advisory_lock`). The lock disappears with the worker's connection, so a run row left
  open by a killed worker is recognized by the next lock holder and closed as failed
  (`interrupted`) before the new run starts.
- **Several workers:** any number may run. Mailboxes and jobs are shared out by the locks, never
  run twice. Retention and reverse-DNS enrichment run under one global try-lock.
- **Graceful shutdown:** SIGTERM finishes the current message, closes the run as failed
  (`interrupted`, so the next run retries what is left), releases the locks and exits 0.
- **No domains, no ingest:** a mailbox configured in the panel will not ingest while no monitored
  domain is configured (and `ALLOWED_DOMAINS` is unset). The run fails with a message saying
  so, rather than accepting reports about any domain.
- **Unchanged:** `run`, `import` and `enrich`, their JSON and exit codes, and the Vercel adapter
  keep working from the environment as documented. They also pick up panel-configured monitored
  domains and retention unless the environment sets them.

**Screens** (admin):
- **Admin → Mail**: the mailboxes, each with its state (last run, next run, last error) and
  whether a worker is alive. Add or edit a mailbox with kind-specific fields. **Test
  connection** and **Run now** queue a job; the page shows "waiting for the worker" until it
  finishes.
- **Run history** for a mailbox: each run's counts and its per-message errors. That text comes
  from strangers' emails, so it is escaped and shortened.
- **Admin → Domains**: monitored domains (add, remove). `ALLOWED_DOMAINS` is shown read-only when
  set.
- Retention is on the settings page.

**Failure cases, all tested.**
- Wrong password or credentials.
- Token endpoint refusing.
- Mailbox unreachable.
- A message that is not a report, or one that fails to store.
- The database lost mid-run.
- The worker killed mid-run: an orphaned run is closed and the next run proceeds.
- Two workers at once.
- A job for a mailbox that was deleted meanwhile.
- No monitored domains.

**Built as designed, plus:**
- Microsoft 365 and Google mailboxes always connect to `outlook.office365.com` and
  `imap.gmail.com`. The host is not editable for those kinds, so a token is only ever sent to
  its provider. Token endpoints are constants; a Google key file's `token_uri` is ignored.
- A saved secret must be typed again whenever the kind, server, port, security, account, tenant
  or application changes (found by the security review: otherwise an admin could redirect a
  saved password to their own server, or a Google key to another user's mailbox).
- The worker sends heartbeats from a thread, so a run longer than two minutes is not taken for
  a dead worker.
- Mailboxes and domains are managed by admins and owners; the caller's role is re-read in the
  transaction, as in milestone 2. Every change, request and refusal is audited, and a secret is
  recorded only as `set` / `kept` / `replaced`.
- The web app's `decryptSecret` refuses any purpose but `setting` and `totp`, and a test scans
  the web sources for a decryption of `mailbox`. `secrets:reencrypt` is the one exception, run
  by an operator. It now covers mailbox secrets and the SSO client secret, which it had missed
  since milestone 3.
- One waiting request of each kind per mailbox: asking again while one waits returns that one.
  Requests a worker took and never finished are failed once it has sent no heartbeat for two
  minutes.
- Retention and reverse-DNS backfill in `serve` run in whichever run holds the global
  housekeeping lock; other runs only read their mailbox.
- `RETENTION_DAYS=0` in the environment still means "keep forever", as in 1.1.0, and wins over
  the panel.
- IMAP mailboxes may point at private addresses, since self-hosted mail servers often live
  there. Folder names are limited to letters, digits, spaces and `. _ - / [ ] & +`.
- Docker Compose runs `serve` under a `serve` profile, so a 1.1 setup without `APP_SECRET` starts
  exactly as before.
- Verified locally against a TLS IMAP stand-in and local token endpoints, including a real
  `serve` process killed with `SIGKILL` mid-run. **Microsoft 365 and Google are unverified
  against real tenants.**

## Milestone 5 — Alerting

Rules: a new source failing DMARC above a volume threshold; compliance for a domain
dropping below a threshold; ingest stale; a published DMARC / SPF record changed.
Channels: email (SMTP settings in the panel), generic webhook (signed), Slack-compatible
webhook. Deduplication, quiet periods, a test button, delivery history.

Alert text is built from report data: escape it for each channel, and never follow
redirects or call private addresses from a webhook unless an owner allows it.

Done when: an admin, working only in the browser, sets up SMTP and a Slack-compatible webhook,
creates one rule of each kind, makes each fire from seeded data, and gets exactly one
notification per event (the next evaluation sends nothing more); an event that clears is closed;
the test button and the delivery history (including a failure) work; a webhook aimed at
`127.0.0.1`, `169.254.169.254` or a redirect is refused; hostile report text is neutralized in
every channel; two web replicas never send the same alert twice; and a deployment with no rules
makes no outbound connection and behaves exactly as in milestone 4.

### Design

**Where it runs.** In the web app, in TypeScript, because it needs the compliance queries, the DNS
check results and the settings store, and the worker is optional (Vercel and cron-only installs
have none).
- `lib/alerts/` holds the evaluator, the renderers and the senders.
- **Scheduling:** a timer started from `instrumentation.ts` evaluates every 5 minutes, only where
  the process is long-running (not when `VERCEL` is set). `GET|POST /api/cron/alerts`, behind the
  machine token like the other cron endpoints, does the same for serverless and external
  schedulers.
- **Leader safety:** one evaluation at a time across all replicas, under a PostgreSQL try-lock.
  A second one returns at once.
- **DNS refresh:** while at least one enabled "record changed" rule exists, the in-process timer
  also refreshes DNS checks once a day (the existing `runAndStoreDnsCheck`). Without it a
  self-hosted install with no cron would never have anything to compare.
- Alerts are system-wide, evaluated with the machine scope. Milestone 6 decides who may *see*
  them per domain.

**Data model (migration `0007`).**
- `alert_channels`:
  - `kind`: `email`, `webhook` or `slack`;
  - `name`, `enabled`;
  - `config` (JSONB, not secret): the recipient list for email;
  - `secret`: an encrypted envelope, purpose `alert`, bound to the row. For `slack` it holds the
    webhook URL; for `webhook`, the URL and the signing secret; for `email`, nothing;
  - `secret_updated_at`, audit columns.
- `alert_rules`:
  - `kind`: `new_failing_source`, `compliance_drop`, `ingest_stale` or `dns_changed`;
  - `name`, `enabled`;
  - `domain` (NULL: every monitored domain);
  - `params` (JSONB, validated per kind);
  - `quiet_minutes` (60 to 10080, default 1440);
  - `notify_resolved` (default false);
  - audit columns.
- `alert_rule_channels (rule_id, channel_id)`.
- `alert_events`: one row per condition.
  - `rule_id`, `dedupe_key`, `domain`;
  - `state` (`open` or `resolved`), `first_seen_at`, `last_seen_at`, `resolved_at`;
  - `last_notified_at`, `reminders_sent`;
  - `summary` and `detail` (JSONB): short, bounded values, stored as data and escaped when
    rendered.
  - A partial unique index on `(rule_id, dedupe_key) WHERE state = 'open'` is what makes
    deduplication a database fact rather than a convention.
- `alert_deliveries` is the outbox and the history:
  - `event_id` (NULL for a test), `channel_id`, `kind` (`alert`, `reminder`, `resolved`, `test`);
  - `status` (`queued`, `sent`, `failed`), `attempts`, `next_attempt_at`;
  - `error` (short, never a secret or a response body), `created_at`, `finished_at`.
- Settings: `smtp.host`, `smtp.port`, `smtp.security` (`ssl` or `starttls`; no plaintext option),
  `smtp.username`, `smtp.password` (secret), `smtp.from`, and `alerts.allow_private_webhooks`
  (default false). All owner-only, each with an environment variable (`SMTP_*`,
  `ALERTS_ALLOW_PRIVATE_WEBHOOKS`).
- Retention: resolved events and their deliveries older than 180 days are deleted by the
  evaluator.

**Rules.** Missing data is never read as "all fine" or as "everything failed".
1. **New source failing** (`min_messages` 100, `window_days` 7): a source IP with at least
   `min_messages` messages failing DMARC for a domain in the window, and no records for that IP
   and domain before the window. Key: `domain|ip`. It resolves when the IP stops matching (it
   ages out of "new", or stops failing).
2. **Compliance dropped** (`threshold_pct` 95, `min_messages` 100, `window_days` 7): the DMARC
   pass rate over the window is below the threshold with at least `min_messages` messages. Under
   `min_messages` there is no verdict, not 0%. Key: `domain`. It resolves when the rate is back
   at or above the threshold.
3. **Ingest stale:** uses the existing `getIngestHealth` and the `ingest.stale_hours` setting.
   `never` (fresh install) is not stale. Key: `ingest`.
4. **Record changed:** the published DMARC or SPF record text differs between the latest two DNS
   checks of a domain. A lookup that timed out or failed is not a record and is never compared;
   NXDOMAIN or "no record" is a real value, so a record that disappeared does alert. A domain with
   one check has nothing to compare. Key: `domain|dmarc|<hash of the new record>`. It is a
   one-time event: it resolves after the next check that agrees with the new record. Before
   building, check how a failed lookup is stored in `dns_checks.results`; if it cannot be told
   apart from "no record", add an explicit marker (the change is made in `lib/dns-checks.ts` and
   tested).

**Lifecycle.** Each evaluation, per rule, in its own transaction (a failing rule is recorded
and the others proceed): compute the current conditions, open new events, update `last_seen_at`
on continuing ones, resolve events whose condition is gone.
- A new event queues one delivery per channel of its rule.
- A still-open event gets a reminder after `quiet_minutes`, repeated at the same interval at most
  3 times, and then goes quiet until it resolves.
- A resolved event sends one notice only if `notify_resolved`.
- Evaluating again with nothing changed queues nothing.

**Delivery.** A sender claims queued deliveries with `FOR UPDATE SKIP LOCKED`, so replicas
cannot send the same one twice, and runs outside the transaction.
- A failure schedules a retry after 1, 5 and 30 minutes (4 attempts in all), then stays `failed`.
- A channel that is down never blocks the others.
- A secret that cannot be decrypted (a rotated `APP_SECRET`) fails the delivery as "secret
  unreadable" without retrying.
- A channel deleted or disabled meanwhile cancels its queued deliveries.
- A deliberate trade-off: a send that succeeded but whose acknowledgement was lost may be
  repeated, so delivery is at-least-once. The webhook carries a stable `event_id` for receivers
  to deduplicate on.

**Channels.**
- **Email:** an SMTP client written on `node:net` / `node:tls`, since the plan prefers what Node
  ships, with a stand-in server in the tests.
  - Certificate verification is always on.
  - It speaks implicit TLS or STARTTLS, with AUTH PLAIN or LOGIN, plain text bodies and dot
    stuffing.
  - Every header value is refused if it contains CR or LF.
  - The subject is RFC 2047 encoded.
  - Recipients are validated addresses, at most 10 per channel.
  - Timeouts: 10 s to connect, 30 s in all.
  - The SMTP server may be on a private address (relays often are); only an owner can set it.
- **Webhook (signed):** `POST` of a JSON body with:
  - `X-DMARCscope-Event-Id`;
  - `X-DMARCscope-Timestamp`;
  - `X-DMARCscope-Signature: v1=<hex HMAC-SHA256 of "<timestamp>.<body>">`.

  The documentation shows receivers how to verify it and reject old timestamps.
- **Slack-compatible:** `POST {"text": ...}` with the characters `& < >` escaped as Slack
  documents, which also neutralizes `<!channel>` and `<http://...|label>`. Not signed.
- **Outbound request rules (webhook and Slack, applied on every delivery, not only when saved):**
  - HTTPS only.
  - Redirects are never followed: any 3xx is a failure.
  - The hostname is resolved first, and the request is made to *that* address (the lookup is
    pinned), so a name cannot change its answer between the check and the connection.
  - Loopback, private, link-local (including `169.254.169.254`), unique-local, CGNAT,
    multicast, unspecified and IPv4-mapped forms of these are refused. `alerts.allow_private_webhooks`
    (owner only) lifts the address rule and also permits `http://`.
  - 10 s timeout; the response body is read to at most 4 KB and never stored or shown.
  - The saved URL is never sent back to the browser: forms show "set" and the host only.

**Escaping.** An alert is a structured object, not a string; each channel has a renderer.
- Fields that came from reports (reverse DNS, organization name, envelope-from, domain) are
  reduced to printable characters and cut to 200.
- Email: plain text, with CR and LF removed from anything in a header.
- Webhook: JSON as data.
- Slack: escaped as above.
- The panel: React's escaping.
- Tests feed each renderer `<!channel>`, `\r\nBcc: x@evil`, a 10 000-character name, control
  characters, and a markdown or Slack link.
- The web app's `decryptSecret` gains purpose `alert`, used only by the sender, and the test that
  scans the web sources for decryptions is extended to allow exactly that one place.

**Screens** (admin and owner; the caller's role is re-read in the transaction, as in
milestone 2).
- **Admin → Alerts:**
  - The evaluator's state: last evaluation, last error, next due.
  - The open events, and the recent ones with their deliveries.
  - The rules, each with its channels and open count, and a form to add or edit one with
    kind-specific fields.
  - The channels, with **Send test** (rate limited to one per channel every 10 seconds), and a
    delivery history showing failures with their short error.
- **Admin → Settings:** the SMTP block, and the private-webhook switch, for the owner.
- Every change, test and refusal is audited; a secret is recorded only as `set` / `kept` /
  `replaced`. As in milestone 4, changing a channel's kind or recipient host requires typing its
  secret again.

**Failure cases, all tested.**
- SMTP: refused, authentication failure, invalid certificate, timeout, a header-injection attempt.
- Webhook: 4xx, 5xx, timeout, a redirect, a private target, a name that resolves to a private
  address, an oversized response.
- A channel deleted meanwhile; a secret that cannot be decrypted.
- Two evaluators at once; two senders at once.
- A rule that throws, with the others still evaluated.
- Hostile report data in every renderer.
- A DNS lookup failure not read as a record change; no data not read as 0%.
- A deployment with no rules makes no outbound connection.

**Unverified until a real service is used:** delivery to a real SMTP provider and to Slack /
Microsoft Teams / Mattermost incoming webhooks. Tests use local stand-ins; the pull request and
`docs/alerts.md` say so.

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
