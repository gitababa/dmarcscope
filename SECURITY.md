# Security

## Reporting a vulnerability

Please report security issues privately through GitHub's **Report a vulnerability** button
(Security → Advisories) on this repository rather than in a public issue. Include what you
found, how to reproduce it, and the version or commit. You should get a response within a
week.

## Security model

DMARCscope is read-only with respect to mail: it cannot send, block or alter messages. What it
protects is the report data — which reveals who sends mail for your domains and from where —
and the mailbox and database credentials it is configured with.

**Authentication and access**

- Every route except the sign-in pages, health probes and bearer-protected machine endpoints
  requires an authorized session. This is enforced in the request proxy and again in each
  page and action.
- Access is deny-by-default; the access lists are checked on every request. With built-in
  OIDC sign-in, the identity and groups are those the provider gave at sign-in and are fixed
  until the session expires (12 hours by default, 7 days at most); `SESSION_NOT_BEFORE`
  invalidates sessions early. See "Removing someone's access" in
  [docs/authentication.md](docs/authentication.md).
- A domain rule (`ALLOWED_EMAIL_DOMAINS`) is only an organization boundary if the provider
  is. With a shared provider such as Google, pin the organization with
  `OIDC_REQUIRED_CLAIMS`.
- OIDC sign-in requires `email_verified: true` for the standard `email` claim.
- Built-in OIDC sign-in uses the authorization-code flow with PKCE, `state` and `nonce`. The
  session is an encrypted (AES-256-GCM) `HttpOnly`, `SameSite=Lax` cookie, `Secure` and
  `__Host-`-prefixed when served over https.
- Proxy assertions (`proxy-jwt`) are verified on every request: signature, issuer, audience,
  expiry; asymmetric algorithms only.
- Plain-header proxy mode requires a shared secret or an explicit acknowledgement in
  production.
- Machine endpoints compare bearer tokens in constant time and are closed when no secret is
  configured.
- State-changing actions are Next.js server actions, which reject cross-origin requests.

**Input handling**

- All SQL is parameterized.
- Report emails are untrusted input. They are parsed by
  [parsedmarc](https://github.com/domainaware/parsedmarc) with network access disabled, and
  text fields are length-limited before storage. Anyone can email a report to the mailbox:
  set `ALLOWED_DOMAINS` so that reports about domains you do not own are ignored. Without
  it, a sender can make arbitrary domains appear on the dashboard and have them DNS-checked.
- DNS checks can only be run for domains already present in the database, by admins, and are
  rate-limited per domain. Names taken from reports are validated before they are used in a
  DNS query, and walking a domain's SPF record is bounded in lookups and in total time.

**Browser hardening**

A per-request, nonce-based Content-Security-Policy; `frame-ancestors 'none'`,
`X-Content-Type-Options`, `Referrer-Policy`, HSTS. The UI loads no third-party resources.

**Operational notes**

- Terminate TLS in front of the app and set `APP_URL` to the https URL.
- Keep `SESSION_SECRET`, `CRON_SECRET`, `IMAP_PASSWORD` and `DATABASE_URL` in a secret
  manager. Rotating `SESSION_SECRET` signs everyone out.
- Give the mailbox account access to the reports mailbox only, and the database user access
  to this database only.
- Containers run as non-root users.
