// Built-in sign-in against any OpenID Connect provider (Google, Microsoft
// Entra ID, Okta, Keycloak, Auth0, Authentik, ...): authorization-code flow
// with PKCE, state and nonce, handled by the openid-client library.
//
// The connection comes from one of two places, described by OidcSettings:
//   - the environment (AUTH_PROVIDER=oidc, OIDC_*), as in 1.1.0;
//   - the database (AUTH_PROVIDER unset, configured and tested in the panel,
//     lib/sso.ts).
// The same rules apply to both: https issuer, verified email, the address
// from exactly one claim, required claims.

import { createHash } from 'node:crypto'
import * as oidc from 'openid-client'
import { ConfigError, appUrl, envBool, type Env } from '../config'
import { relevantGroups } from './authz'
import type { LoginState } from './session'
import type { Identity } from './types'

export class LoginError extends Error {
  // `code` is a stable identifier shown to the user via /login?error=<code>.
  constructor(
    public code: 'unverified_email' | 'no_email' | 'wrong_account' | 'failed' | 'expired',
    message: string
  ) {
    super(message)
    this.name = 'LoginError'
  }
}

export type OidcSettings = {
  issuer: string
  clientId: string
  clientSecret: string | null
  scopes: string
  emailClaim: string
  groupsClaim: string
  requiredClaims: string
  prompt: string | null
  // Environment-only switches (trusted): a local test provider over http,
  // and a provider that does not send email_verified.
  allowInsecureIssuer: boolean
  allowUnverifiedEmail: boolean
}

export function oidcSettingsFromEnv(env: Env = process.env): OidcSettings {
  const issuer = env.OIDC_ISSUER?.trim()
  const clientId = env.OIDC_CLIENT_ID?.trim()
  if (!issuer || !clientId) {
    throw new ConfigError('AUTH_PROVIDER=oidc requires OIDC_ISSUER and OIDC_CLIENT_ID (and normally OIDC_CLIENT_SECRET).')
  }
  return {
    issuer,
    clientId,
    clientSecret: env.OIDC_CLIENT_SECRET?.trim() || null,
    scopes: env.OIDC_SCOPES?.trim() || 'openid email profile',
    emailClaim: env.OIDC_EMAIL_CLAIM?.trim() || 'email',
    groupsClaim: env.OIDC_GROUPS_CLAIM?.trim() || 'groups',
    requiredClaims: env.OIDC_REQUIRED_CLAIMS ?? '',
    prompt: env.OIDC_PROMPT?.trim() || null,
    allowInsecureIssuer: envBool(env.OIDC_ALLOW_INSECURE_ISSUER),
    allowUnverifiedEmail: envBool(env.OIDC_ALLOW_UNVERIFIED_EMAIL),
  }
}

// Checks the issuer before any network request.
export function issuerUrl(settings: OidcSettings): URL {
  let url: URL
  try {
    url = new URL(settings.issuer)
  } catch {
    throw new ConfigError('The issuer is not a valid URL.')
  }
  if (url.protocol === 'http:' && !settings.allowInsecureIssuer) {
    throw new ConfigError('The issuer must use https. (For a local test provider only, set OIDC_ALLOW_INSECURE_ISSUER=true.)')
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') throw new ConfigError('The issuer must use https.')
  return url
}

const cache = new Map<string, Promise<oidc.Configuration>>()

function getConfiguration(settings: OidcSettings): Promise<oidc.Configuration> {
  const url = issuerUrl(settings)
  // The secret is part of the key (as a digest), so replacing it is never
  // answered from a configuration built with the old one.
  const secretKey = settings.clientSecret ? createHash('sha256').update(settings.clientSecret).digest('hex') : 'public'
  const key = `${settings.issuer}|${settings.clientId}|${secretKey}|${settings.allowInsecureIssuer}`
  const hit = cache.get(key)
  if (hit) return hit
  const config = oidc
    .discovery(
      url,
      settings.clientId,
      settings.clientSecret || undefined,
      // No secret → public client relying on PKCE alone.
      settings.clientSecret ? undefined : oidc.None(),
      url.protocol === 'http:' ? { execute: [oidc.allowInsecureRequests] } : undefined
    )
    .catch((err) => {
      // Don't cache a failed discovery (the IdP may just be briefly down).
      cache.delete(key)
      throw err
    })
  if (cache.size > 20) cache.clear()
  cache.set(key, config)
  return config
}

// Fetches and validates the provider's discovery document: a test of the
// issuer before sending anyone there.
export async function discover(settings: OidcSettings): Promise<void> {
  await getConfiguration(settings)
}

export function redirectUri(env: Env = process.env): string {
  return `${appUrl(env)}/auth/callback`
}

export async function beginLoginWith(
  settings: OidcSettings,
  returnTo: string,
  env: Env = process.env
): Promise<{ url: string; state: LoginState }> {
  parseRequiredClaims(settings.requiredClaims) // surface a malformed value before the round trip
  const config = await getConfiguration(settings)
  const codeVerifier = oidc.randomPKCECodeVerifier()
  const state = oidc.randomState()
  const nonce = oidc.randomNonce()

  const params: Record<string, string> = {
    redirect_uri: redirectUri(env),
    scope: settings.scopes,
    code_challenge: await oidc.calculatePKCECodeChallenge(codeVerifier),
    code_challenge_method: 'S256',
    state,
    nonce,
  }
  // e.g. "select_account" to always show the account chooser
  if (settings.prompt) params.prompt = settings.prompt

  return {
    url: oidc.buildAuthorizationUrl(config, params).href,
    state: { state, nonce, codeVerifier, returnTo },
  }
}

export async function beginLogin(returnTo: string, env: Env = process.env): Promise<{ url: string; state: LoginState }> {
  return beginLoginWith(oidcSettingsFromEnv(env), returnTo, env)
}

function asString(v: unknown): string | undefined {
  return typeof v === 'string' && v.trim() ? v.trim() : undefined
}

function asStringList(v: unknown): string[] {
  if (Array.isArray(v)) return v.filter((x): x is string => typeof x === 'string')
  if (typeof v === 'string' && v) return v.split(/[,\s]+/).filter(Boolean)
  return []
}

const looksLikeEmail = (v: string | undefined): v is string => Boolean(v && /^[^@\s]+@[^@\s]+$/.test(v))

// The code exchange: validated ID token claims (plus UserInfo where the ID
// token lacks the address or groups). Throws on any protocol error.
export async function exchangeCode(
  settings: OidcSettings,
  callbackUrl: URL,
  login: LoginState,
  env: Env = process.env
): Promise<Record<string, unknown>> {
  const config = await getConfiguration(settings)

  // The provider redirects to APP_URL/auth/callback; rebuild the URL from
  // configuration rather than trusting the Host header we were reached on.
  const currentUrl = new URL(redirectUri(env))
  currentUrl.search = callbackUrl.search

  const tokens = await oidc.authorizationCodeGrant(config, currentUrl, {
    pkceCodeVerifier: login.codeVerifier,
    expectedState: login.state,
    expectedNonce: login.nonce,
    idTokenExpected: true,
  })
  const claims: Record<string, unknown> = { ...(tokens.claims() ?? {}) }
  const sub = asString(claims.sub)
  if (!sub) throw new LoginError('failed', 'ID token has no subject')

  // Some providers only return email / groups from the UserInfo endpoint.
  if ((!asString(claims[settings.emailClaim]) || claims[settings.groupsClaim] == null) && config.serverMetadata().userinfo_endpoint) {
    try {
      const info = await oidc.fetchUserInfo(config, tokens.access_token, sub)
      for (const [k, v] of Object.entries(info)) if (claims[k] == null) claims[k] = v
    } catch {
      // UserInfo is optional; fall through with what the ID token gave us.
    }
  }
  return claims
}

export async function completeLogin(
  callbackUrl: URL,
  login: LoginState,
  env: Env = process.env,
  extraGroups: readonly string[] = []
): Promise<Identity> {
  const settings = oidcSettingsFromEnv(env)
  return identityFromClaimsWith(settings, await exchangeCode(settings, callbackUrl, login, env), env, extraGroups)
}

// OIDC_REQUIRED_CLAIMS="hd=example.com,tid=1111|2222": every listed claim must
// be present with one of the given values. This is what ties a sign-in to an
// organization when the provider is shared (Google's `hd`, Entra's `tid`).
export function parseRequiredClaims(raw: string | undefined): Array<{ claim: string; values: string[] }> {
  const out: Array<{ claim: string; values: string[] }> = []
  for (const part of (raw || '').split(',')) {
    if (!part.trim()) continue
    const eq = part.indexOf('=')
    const claim = eq === -1 ? '' : part.slice(0, eq).trim()
    const values = eq === -1 ? [] : part.slice(eq + 1).split('|').map((v) => v.trim()).filter(Boolean)
    if (!claim || values.length === 0) {
      throw new ConfigError('OIDC_REQUIRED_CLAIMS must look like "claim=value,other=value1|value2".')
    }
    out.push({ claim, values })
  }
  return out
}

function claimMatches(actual: unknown, allowed: string[]): boolean {
  const present = Array.isArray(actual) ? actual : [actual]
  return present.some((v) => (typeof v === 'string' || typeof v === 'number' || typeof v === 'boolean') && allowed.includes(String(v)))
}

// Turns validated token claims into an identity, or refuses the sign-in.
export function identityFromClaimsWith(
  settings: OidcSettings,
  claims: Record<string, unknown>,
  env: Env = process.env,
  extraGroups: readonly string[] = []
): Identity {
  const sub = asString(claims.sub)
  if (!sub) throw new LoginError('failed', 'ID token has no subject')

  for (const { claim, values } of parseRequiredClaims(settings.requiredClaims)) {
    if (!claimMatches(claims[claim], values)) {
      throw new LoginError('wrong_account', `Required claim "${claim}" is missing or has a value that is not allowed`)
    }
  }

  // The address comes from exactly one claim. To use a provider's sign-in
  // name instead (Entra ID often issues no `email`), name that claim
  // explicitly, e.g. preferred_username.
  const email = asString(claims[settings.emailClaim])
  if (!looksLikeEmail(email)) {
    throw new LoginError('no_email', `The identity provider did not return an email address in the "${settings.emailClaim}" claim`)
  }
  // `email_verified` describes the standard `email` claim only. Anything
  // other than an explicit true counts as unverified.
  if (settings.emailClaim === 'email' && claims.email_verified !== true && !settings.allowUnverifiedEmail) {
    throw new LoginError('unverified_email', 'The identity provider did not confirm this email address as verified')
  }

  return {
    sub,
    email: email.toLowerCase(),
    name: asString(claims.name),
    groups: relevantGroups(asStringList(claims[settings.groupsClaim]), env, extraGroups),
  }
}

export function identityFromClaims(claims: Record<string, unknown>, env: Env = process.env, extraGroups: readonly string[] = []): Identity {
  return identityFromClaimsWith(oidcSettingsFromEnv({ OIDC_ISSUER: 'https://unused.invalid', OIDC_CLIENT_ID: 'unused', ...env }), claims, env, extraGroups)
}

// RP-initiated logout URL, when enabled and the provider supports it
// (environment-configured connections only).
export async function endSessionUrl(env: Env = process.env): Promise<string | null> {
  if (!envBool(env.OIDC_LOGOUT_AT_IDP)) return null
  try {
    const settings = oidcSettingsFromEnv(env)
    const config = await getConfiguration(settings)
    if (!config.serverMetadata().end_session_endpoint) return null
    return oidc.buildEndSessionUrl(config, {
      client_id: settings.clientId,
      post_logout_redirect_uri: `${appUrl(env)}/login?signed_out=1`,
    }).href
  } catch {
    return null
  }
}
