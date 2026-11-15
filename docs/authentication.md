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

Roles are evaluated on every request, so removing someone takes effect immediately, without
waiting for their session to expire. Someone who is authenticated but matches no rule sees an
"Access not granted" page showing the address they signed in with.

Use `AUTH_ALLOW_ANY_AUTHENTICATED` only when the provider itself is limited to your
organization (a single-tenant IdP, or an access proxy with its own policy). A public
"Sign in with Google" client authenticates any Google account.

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
| Google | `https://accounts.google.com` | Set `ALLOWED_EMAIL_DOMAINS` or `ALLOWED_EMAILS`. Google does not issue a groups claim. |
| Microsoft Entra ID | `https://login.microsoftonline.com/<tenant-id>/v2.0` | Use a single-tenant app registration. The `groups` claim (if enabled) contains group object IDs — put those IDs in `ADMIN_GROUPS` / `ALLOWED_GROUPS`. If no `email` claim is issued, the sign-in name (`preferred_username`) is used. |
| Okta | `https://<org>.okta.com` or `https://<org>.okta.com/oauth2/default` | Add a `groups` claim to the ID token to use group rules. |
| Keycloak | `https://<host>/realms/<realm>` | Add a group-membership mapper named `groups`. |
| Auth0, Authentik, Zitadel, … | the issuer shown in the provider's OIDC settings | |

Optional settings: `OIDC_PROVIDER_NAME` (button label), `OIDC_SCOPES`, `OIDC_GROUPS_CLAIM`,
`OIDC_EMAIL_CLAIM`, `OIDC_PROMPT`, `SESSION_MAX_AGE_HOURS` (default 12) and
`OIDC_LOGOUT_AT_IDP=true` to also end the provider session on sign-out.

Sign-in is refused when the provider reports `email_verified: false`.

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
The keys must be served as a JWKS over https. Only asymmetric signature algorithms are
accepted.

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

`/api/healthz` and `/api/readyz` are unauthenticated and return only `{"ok": true|false}`.

## Audit log

Sign-ins, denied sign-ins, sign-outs and DNS checks are written to stdout as JSON lines with
`"type":"audit"`, for whatever log pipeline the platform provides.
