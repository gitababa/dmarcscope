# Authentication and access

Two separate questions are answered separately:

1. **Who is this?** — `AUTH_PROVIDER` chooses how a request is authenticated. Leave it unset to
   manage sign-in in the app itself.
2. **May they come in, and with which role?** — the users table and the access rules decide, the
   same way for every provider, on every request.

## Roles

| Role | May |
|---|---|
| **owner** | everything, including sign-in and secret settings |
| **admin** | users, mailbox, domains, alerts, DNS checks, ordinary settings |
| **viewer** | read the dashboards |

There is one owner, created by the setup wizard. Access rules can grant admin or viewer, never
owner.

## Sign-in managed in the app (`AUTH_PROVIDER` unset)

With only `DATABASE_URL`, `APP_URL` and `APP_SECRET` set, the app manages sign-in itself:

- Until an owner exists, it serves **only the setup wizard** (`/setup`). Every other page sends
  you there, and `/api/*` answers 503 `{"error":"setup_required"}`. The probes keep working.
- The owner signs in with an email address, a password and a code from an authenticator app
  (TOTP), or a recovery code instead of the app code.
- Single sign-on (any OpenID Connect provider) is configured, tested and activated in the panel
  under **Sign-in**: see [sso.md](sso.md). Until a connection is active, the owner is
  the only person who can sign in in this mode.

### First run: the setup wizard

1. When the app starts and no owner exists, it prints a one-time **setup token** to its log:

   ```
   [setup] No owner account exists yet. Open https://dmarc.example.com/setup and enter this one-time setup token (valid for 24 hours): …
   ```

   The token is stored only as a digest and is valid for 24 hours. It is never shown on the page:
   only someone who can read the server log can create the owner. If the line is gone (a
   platform that keeps an hour of logs, a missed start) or the token expired, press **Write a
   new token to the log** on `/setup`: earlier tokens keep working, at most five are usable at
   once, and a new one can be requested once a minute. The page also says when the newest token
   was written and where to look on each platform ([deployment.md](deployment.md#first-start-create-the-owner)).
   To choose the token yourself instead, set `SETUP_TOKEN` (at least 24 characters).
2. Open `/setup`, enter the token, then the owner's email address, name and password (at least 12
   characters; the most common passwords are refused).
3. Scan the QR code with an authenticator app and enter the code it shows.
4. You are signed in as the owner and shown ten **recovery codes**, once. Each signs you in once
   in place of an app code. Keep them in a password manager.

After that, `/setup` answers 404 for good. Wrong, expired and already-used tokens are refused,
and so are repeated wrong guesses from one address.

The wizard also works on a deployment that has `AUTH_PROVIDER` set (for example one upgraded from
1.1.0): it creates the owner, who can then sign in with the password from the "Owner sign-in"
link on the sign-in page (`oidc`) or is recognized by address (`proxy-jwt`, `proxy-header`, where
the wizard uses the address the proxy signed you in with). Such deployments are not locked to
the wizard: until an owner is created, they work exactly as before.

### Password sign-in protections

- Passwords are hashed with scrypt; the parameters are stored with each hash so they can be
  raised later.
- A wrong password, an unknown address and an account that may not sign in with a password all
  get the same answer and take the same time.
- Five failures in a row lock the account for a minute, doubling with every further failure up
  to an hour; addresses that have no account lock the same way, so a lockout does not reveal
  whether an account exists. Twenty failures from one client address lock that address. A
  successful sign-in resets the account's count.
- Each TOTP code works once: a code that has been used, or an older one, is refused.

The per-address limit relies on `CLIENT_IP_HEADER` (see [configuration.md](configuration.md));
the per-account lockout does not.

## Users and pending requests

Everyone who signs in is recorded in the users table:

- someone an access rule admits is recorded as **active**, with the rule's role;
- someone no rule admits is recorded as a **pending** request and sees "Access not granted"
  until an administrator approves them (or a rule starts admitting them);
- someone **invited** in the panel gets the invited role at their first sign-in;
- a **disabled** user is refused whatever the rules say.

A role that came from a rule is worked out again on every request, so removing the rule removes
the access, as it always did.

### Managing people (People, Access rules)

Administrators and the owner can:

| Action | Effect |
|---|---|
| Approve / reject a request | Approve gives the chosen role. Reject disables the request: the person stays refused, and can be re-enabled later. |
| Invite | Gives an address a role before the person first signs in through single sign-on or the access proxy. No email is sent. |
| Change role | Takes effect on the person's next request; the role is then fixed (`assigned`) rather than coming from a rule. |
| Disable / enable | Disabled people are refused from their next request on. |
| Sign out everywhere | Ends every session the person has (`sessions_valid_after`). |
| Remove | Deletes the user; their history stays in the audit log. If a rule admits them, they come back as a new user at their next sign-in, so disable them to keep them out. |
| Add / delete access rules | An email domain or a group, giving admin or viewer. Applies within `SETTINGS_CACHE_SECONDS` everywhere. |

Guard rails, enforced on the server whatever the page showed:

- an admin can change only admins and viewers, and give only those roles; only an owner can
  change an owner or make someone an owner;
- nobody can disable or remove their own account;
- the last active owner cannot be demoted, disabled or removed;
- every change, and every refused attempt, is recorded in the audit log.

**Audit log** filters by action, who, target and date, and downloads the filtered log as
CSV (at most 100,000 rows; the download itself is recorded). Cells a spreadsheet would treat as a
formula are prefixed with `'`.

## Access rules (all providers)

Access is **denied by default**. Being able to sign in at the identity provider is not enough;
a person must match at least one rule (or have been given a role). Rules come from two places:
the environment variables below, which cannot be changed in the panel, and the database, where
`npm run settings:import` can copy them (and the panel will manage them in a later 2.0 release).
All values are comma-separated and case-insensitive. Database rules are managed under
**Access rules**, which also lists the environment's rules (read-only).

| Variable | Grants |
|---|---|
| `ADMIN_EMAILS`, `ADMIN_GROUPS` | **admin**: everything a viewer can do, plus running DNS checks |
| `ALLOWED_EMAILS` | **viewer** for these addresses |
| `ALLOWED_EMAIL_DOMAINS` | **viewer** for everyone with an address at these domains |
| `ALLOWED_GROUPS` | **viewer** for members of these groups (group claim or groups header) |
| `AUTH_ALLOW_ANY_AUTHENTICATED=true` | **viewer** for anyone the provider authenticates |

Someone who is authenticated but matches no rule sees an "Access not granted" page showing the
address they signed in with.

Use `AUTH_ALLOW_ANY_AUTHENTICATED` only when the provider itself is limited to your
organization (a single-tenant IdP, or an access proxy with its own policy). A public
"Sign in with Google" client authenticates any Google account.

### How strong is each rule?

A rule is only as trustworthy as the email address or group name the provider hands over.

| Setup | What the rule really checks |
|---|---|
| `proxy-jwt` (IAP, Cloudflare Access) | An address the proxy authenticated, re-verified on every request. Strongest. |
| `oidc`, provider limited to your organization (single-tenant Entra / Okta / Keycloak) | An address your own directory issued. |
| `oidc`, shared provider (Google), `ALLOWED_EMAILS` | Those exact accounts. |
| `oidc`, shared provider (Google), `ALLOWED_EMAIL_DOMAINS` only | **Any** Google account with an address at that domain — including personal Google accounts registered with a work address, and accounts of people who have left. Add `OIDC_REQUIRED_CLAIMS=hd=<your domain>` so only accounts managed by your Workspace are accepted. |
| `proxy-header` | Whatever the proxy puts in the header. Make sure it overwrites both the email and the groups header on every request. |

### Moving the access lists into the database

`npm run settings:import` (in the image: `node scripts/settings-import.mjs`) copies the
environment's lists into the database: `ADMIN_EMAILS` and `ALLOWED_EMAILS` become users with
that role, `ALLOWED_EMAIL_DOMAINS`, `ADMIN_GROUPS` and `ALLOWED_GROUPS` become access rules.
Running it again changes nothing; it never lowers a role, never touches the owner and never
re-enables a disabled user. After it, the variables can be removed.
`AUTH_ALLOW_ANY_AUTHENTICATED` has no database equivalent and stays in the environment.
`--dry-run` shows what it would do.

### Removing someone's access

How quickly a removal takes effect depends on where you remove them:

| You change | Takes effect |
|---|---|
| An access list (`ALLOWED_*`, `ADMIN_*`) | When the app restarts with the new value — the lists are environment variables, checked on every request. |
| A database access rule | Within `SETTINGS_CACHE_SECONDS` (default 5) on every instance. |
| The person in **People**: disabled, role changed, removed, or "sign out everywhere" | On their next request. |
| The person's account or groups at the provider, with `proxy-jwt` / `proxy-header` | On their next request (as fast as the proxy enforces it). |
| The person's account or groups at the provider, with `oidc` | When their session expires: the identity and groups are fixed at sign-in for `SESSION_MAX_AGE_HOURS` (default 12, maximum 168). |

To cut `oidc` sessions short, set `SESSION_NOT_BEFORE` to the current time (ISO format, e.g.
`2026-01-31T09:00:00Z`) and restart: every session issued before that moment is rejected and
those users have to sign in again. Changing `SESSION_SECRET` has the same effect.

## `AUTH_PROVIDER=oidc` — built-in sign-in

Works with any OpenID Connect provider. Authorization-code flow with PKCE; the session is an
encrypted, HttpOnly cookie, so no session store is needed and any number of replicas can serve
the same user.

```bash
AUTH_PROVIDER=oidc
APP_URL=https://dmarc.example.com
OIDC_ISSUER=...
OIDC_CLIENT_ID=...
OIDC_CLIENT_SECRET=...
SESSION_SECRET=$(openssl rand -base64 32)
```

Register `https://dmarc.example.com/auth/callback` as the redirect URI with the provider.

| Provider | `OIDC_ISSUER` | Notes |
|---|---|---|
| Google | `https://accounts.google.com` | Set `ALLOWED_EMAILS`, or `ALLOWED_EMAIL_DOMAINS` together with `OIDC_REQUIRED_CLAIMS=hd=<your Workspace domain>`. Google does not issue a groups claim. |
| Microsoft Entra ID | `https://login.microsoftonline.com/<tenant-id>/v2.0` | Use a single-tenant app registration. Entra does not issue `email_verified`, and its `email` claim is an editable directory attribute, so set `OIDC_EMAIL_CLAIM=preferred_username` to identify people by their sign-in name. The `groups` claim (if enabled) contains group object IDs — put those IDs in `ADMIN_GROUPS` / `ALLOWED_GROUPS`. |
| Okta | `https://<org>.okta.com` or `https://<org>.okta.com/oauth2/default` | Add a `groups` claim to the ID token to use group rules. |
| Keycloak | `https://<host>/realms/<realm>` | Add a group-membership mapper named `groups`. |
| Auth0, Authentik, Zitadel, … | the issuer shown in the provider's OIDC settings | |

Optional settings: `OIDC_PROVIDER_NAME` (button label), `OIDC_SCOPES`, `OIDC_GROUPS_CLAIM`,
`OIDC_EMAIL_CLAIM`, `OIDC_PROMPT`, `SESSION_MAX_AGE_HOURS` (default 12), `SESSION_NOT_BEFORE`
and `OIDC_LOGOUT_AT_IDP=true` to also end the provider session on sign-out.

**Which claim identifies the person.** The address is read from one claim: `email`, or the one
named by `OIDC_EMAIL_CLAIM`. With the standard `email` claim, sign-in is refused unless the
provider also sends `email_verified: true`; set `OIDC_ALLOW_UNVERIFIED_EMAIL=true` only for a
provider you control that does not send it. A claim you name yourself is taken as is.

**Required claims.** `OIDC_REQUIRED_CLAIMS` lists claims every sign-in must carry, as
`name=value` pairs separated by commas; `|` separates alternatives
(`hd=example.com,tid=1111|2222`). Values are compared exactly. A sign-in that does not match
is refused before any access rule is looked at. Use it to pin a shared provider to your
organization: `hd` for Google Workspace, `tid` for Entra.

`OIDC_ALLOW_INSECURE_ISSUER=true` permits an `http://` issuer, for a local test provider only.

Leaving `OIDC_CLIENT_SECRET` empty configures a public client that relies on PKCE alone.

Changing `SESSION_SECRET` signs everyone out. `SESSION_SECRET` is optional when `APP_SECRET` is set:
without it, the session key is derived from `APP_SECRET`. Existing deployments keep theirs, so
upgrading signs nobody out.

## `AUTH_PROVIDER=proxy-jwt` — Google Cloud IAP, Cloudflare Access

The proxy authenticates the user and passes a **signed** assertion in a request header. The
app verifies the signature against the proxy's published keys, and checks issuer, audience and
expiry, on every request. A request that reaches the app without passing through the proxy
carries no valid assertion and is rejected.

### Google Cloud Identity-Aware Proxy

```bash
AUTH_PROVIDER=proxy-jwt
AUTH_PROXY_PRESET=gcp-iap
AUTH_PROXY_AUDIENCE=/projects/<PROJECT_NUMBER>/global/backendServices/<BACKEND_SERVICE_ID>
ALLOWED_EMAIL_DOMAINS=example.com        # or ALLOWED_EMAILS / AUTH_ALLOW_ANY_AUTHENTICATED
```

The audience is the "signed header JWT audience" shown for the resource in the IAP console;
its format depends on what IAP protects (load balancer backend service, App Engine, or a
Cloud Run service). Who may reach the app at all is controlled in Google Cloud with the
*IAP-secured Web App User* role; the access lists above still apply on top. If IAP's IAM
policy is your single source of truth, set `AUTH_ALLOW_ANY_AUTHENTICATED=true` and list only
`ADMIN_EMAILS`.

IAP assertions carry no group claim, so use email-based rules.

### Cloudflare Access

```bash
AUTH_PROVIDER=proxy-jwt
AUTH_PROXY_PRESET=cloudflare-access
AUTH_PROXY_ISSUER=https://<team>.cloudflareaccess.com
AUTH_PROXY_AUDIENCE=<application AUD tag>
```

### Any other proxy that signs a JWT

Set `AUTH_PROXY_JWT_HEADER`, `AUTH_PROXY_JWKS_URL`, `AUTH_PROXY_ISSUER` and
`AUTH_PROXY_AUDIENCE` (and optionally `AUTH_PROXY_EMAIL_CLAIM`, `AUTH_PROXY_GROUPS_CLAIM`).
The keys must be served as a JWKS over https (`AUTH_PROXY_ALLOW_INSECURE_JWKS=true` lifts
that for a local test proxy only). Only asymmetric signature algorithms are accepted.

## `AUTH_PROVIDER=proxy-header` — oauth2-proxy, nginx `auth_request`, Traefik ForwardAuth

The proxy passes the user's email in a plain header (default `X-Forwarded-Email`; groups in
`X-Forwarded-Groups`, comma-separated).

A plain header can be set by anyone who can reach the app directly, so in production the app
refuses to start serving in this mode unless you do one of:

- **Recommended:** set `AUTH_PROXY_SHARED_SECRET` and have the proxy add it to every request
  as `X-Proxy-Secret`. Requests without it are rejected.
- Set `AUTH_PROXY_TRUST_NETWORK=true` to confirm that network policy makes the app reachable
  only through the proxy.

Make sure the proxy strips these headers from incoming client requests.

Header names are configurable: `AUTH_PROXY_EMAIL_HEADER`, `AUTH_PROXY_GROUPS_HEADER`,
`AUTH_PROXY_NAME_HEADER`, `AUTH_PROXY_SECRET_HEADER`.

## `AUTH_PROVIDER=none`

No sign-in; every visitor has full access (the owner role) and nothing is recorded. For local
development and demos. Refused when
`NODE_ENV=production` unless `AUTH_ALLOW_INSECURE_NONE=true` is also set.

## Machine endpoints

`/api/cron/*` is not behind user sign-in; it requires `Authorization: Bearer <token>`, the token
being `CRON_SECRET` or, when that is unset, the "Machine endpoint token" saved by the owner in
the panel. It rejects everything while neither is set or the token is shorter than 16
characters. If an
access proxy sits in front of the app, either let that path through for your scheduler or call
it from inside the network.

| Endpoint | Purpose |
|---|---|
| `GET /api/cron/dns-check` | Refresh the DNS checks of every domain (`?domain=` for one). |
| `GET /api/cron/status` | Ingest health: `200` while a run has completed within `INGEST_STALE_HOURS`, `503` otherwise. Point a monitor at it. |

`/api/healthz` and `/api/readyz` are unauthenticated and return only `{"ok": true|false}`.

## Audit log

Sign-ins, refused and failed sign-ins, access requests, sign-outs, DNS checks, setting changes,
user changes and every setup step are recorded in the `audit_log` table, which administrators can
read under **Audit log**. The table is append-only: the application has no way to change
or delete an entry, and the database refuses `UPDATE` and `DELETE` on it. Entries record that a
secret changed, never its value.

As in 1.1.0, each entry is also written to stdout as a JSON line with `"type":"audit"`, for
whatever log pipeline the platform provides.
