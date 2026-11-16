# Authentication and access

Two separate questions are answered separately:

1. **Who is this?** — `AUTH_PROVIDER` chooses how a request is authenticated.
2. **May they come in?** — access lists decide, the same way for every provider.

## Access lists (all providers)

Access is **denied by default**. Being able to sign in at the identity provider is not enough;
a person must match at least one rule. All values are comma-separated and case-insensitive.

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

### Removing someone's access

How quickly a removal takes effect depends on where you remove them:

| You change | Takes effect |
|---|---|
| An access list (`ALLOWED_*`, `ADMIN_*`) | When the app restarts with the new value — the lists are environment variables, checked on every request. |
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

Changing `SESSION_SECRET` signs everyone out.

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

No sign-in; every visitor is an admin. For local development and demos. Refused when
`NODE_ENV=production` unless `AUTH_ALLOW_INSECURE_NONE=true` is also set.

## Machine endpoints

`/api/cron/*` is not behind user sign-in; it requires `Authorization: Bearer <CRON_SECRET>`
and rejects everything while `CRON_SECRET` is unset or shorter than 16 characters. If an
access proxy sits in front of the app, either let that path through for your scheduler or call
it from inside the network.

| Endpoint | Purpose |
|---|---|
| `GET /api/cron/dns-check` | Refresh the DNS checks of every domain (`?domain=` for one). |
| `GET /api/cron/status` | Ingest health: `200` while a run has completed within `INGEST_STALE_HOURS`, `503` otherwise. Point a monitor at it. |

`/api/healthz` and `/api/readyz` are unauthenticated and return only `{"ok": true|false}`.

## Audit log

Sign-ins, denied sign-ins, sign-outs and DNS checks are written to stdout as JSON lines with
`"type":"audit"`, for whatever log pipeline the platform provides.
