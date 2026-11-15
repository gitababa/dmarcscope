// Built-in sign-in against any OpenID Connect provider (Google, Microsoft
// Entra ID, Okta, Keycloak, Auth0, Authentik, ...): authorization-code flow
// with PKCE, state and nonce, handled by the openid-client library.

import * as oidc from 'openid-client'
import { ConfigError, appUrl, envBool, type Env } from '../config'
import { relevantGroups } from './authz'
import type { LoginState } from './session'
import type { Identity } from './types'

export class LoginError extends Error {
  // `code` is a stable identifier shown to the user via /login?error=<code>.
  constructor(
    public code: 'unverified_email' | 'no_email' | 'failed' | 'expired',
    message: string
  ) {
    super(message)
    this.name = 'LoginError'
  }
}

let cached: { key: string; config: Promise<oidc.Configuration> } | null = null

function getConfiguration(env: Env): Promise<oidc.Configuration> {
  const issuer = env.OIDC_ISSUER?.trim()
  const clientId = env.OIDC_CLIENT_ID?.trim()
  const clientSecret = env.OIDC_CLIENT_SECRET?.trim()
  if (!issuer || !clientId) {
    throw new ConfigError('AUTH_PROVIDER=oidc requires OIDC_ISSUER and OIDC_CLIENT_ID (and normally OIDC_CLIENT_SECRET).')
  }
  let issuerUrl: URL
  try {
    issuerUrl = new URL(issuer)
  } catch {
    throw new ConfigError('OIDC_ISSUER is not a valid URL.')
  }
  const insecure = issuerUrl.protocol === 'http:'
  if (insecure && !envBool(env.OIDC_ALLOW_INSECURE_ISSUER)) {
    throw new ConfigError('OIDC_ISSUER must use https. (For a local test provider only, set OIDC_ALLOW_INSECURE_ISSUER=true.)')
  }

  const key = `${issuer}|${clientId}|${clientSecret ? 'secret' : 'public'}`
  if (cached?.key === key) return cached.config

  const config = oidc
    .discovery(
      issuerUrl,
      clientId,
      clientSecret || undefined,
      // No secret → public client relying on PKCE alone.
      clientSecret ? undefined : oidc.None(),
      insecure ? { execute: [oidc.allowInsecureRequests] } : undefined
    )
    .catch((err) => {
      // Don't cache a failed discovery (the IdP may just be briefly down).
      if (cached?.key === key) cached = null
      throw err
    })
  cached = { key, config }
  return config
}

export function redirectUri(env: Env = process.env): string {
  return `${appUrl(env)}/auth/callback`
}

export async function beginLogin(
  returnTo: string,
  env: Env = process.env
): Promise<{ url: string; state: LoginState }> {
  const config = await getConfiguration(env)
  const codeVerifier = oidc.randomPKCECodeVerifier()
  const state = oidc.randomState()
  const nonce = oidc.randomNonce()

  const params: Record<string, string> = {
    redirect_uri: redirectUri(env),
    scope: env.OIDC_SCOPES?.trim() || 'openid email profile',
    code_challenge: await oidc.calculatePKCECodeChallenge(codeVerifier),
    code_challenge_method: 'S256',
    state,
    nonce,
  }
  // e.g. "select_account" to always show the account chooser
  if (env.OIDC_PROMPT?.trim()) params.prompt = env.OIDC_PROMPT.trim()

  return {
    url: oidc.buildAuthorizationUrl(config, params).href,
    state: { state, nonce, codeVerifier, returnTo },
  }
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

export async function completeLogin(
  callbackUrl: URL,
  login: LoginState,
  env: Env = process.env
): Promise<Identity> {
  const config = await getConfiguration(env)

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

  const emailClaim = env.OIDC_EMAIL_CLAIM?.trim() || 'email'
  const groupsClaim = env.OIDC_GROUPS_CLAIM?.trim() || 'groups'

  // Some providers only return email / groups from the UserInfo endpoint.
  if ((!asString(claims[emailClaim]) || claims[groupsClaim] == null) && config.serverMetadata().userinfo_endpoint) {
    try {
      const info = await oidc.fetchUserInfo(config, tokens.access_token, sub)
      for (const [k, v] of Object.entries(info)) if (claims[k] == null) claims[k] = v
    } catch {
      // UserInfo is optional; fall through with what the ID token gave us.
    }
  }

  let email = asString(claims[emailClaim])
  // Entra ID commonly omits `email` and carries the sign-in name instead.
  if (!looksLikeEmail(email) && emailClaim === 'email') {
    email = [asString(claims.preferred_username), asString(claims.upn)].find(looksLikeEmail)
  }
  if (!looksLikeEmail(email)) {
    throw new LoginError('no_email', 'The identity provider did not return an email address')
  }
  if (claims.email_verified === false && !envBool(env.OIDC_ALLOW_UNVERIFIED_EMAIL)) {
    throw new LoginError('unverified_email', 'The identity provider reports this email address as unverified')
  }

  return {
    sub,
    email: email.toLowerCase(),
    name: asString(claims.name),
    groups: relevantGroups(asStringList(claims[groupsClaim]), env),
  }
}

// RP-initiated logout URL, when enabled and the provider supports it.
export async function endSessionUrl(env: Env = process.env): Promise<string | null> {
  if (!envBool(env.OIDC_LOGOUT_AT_IDP)) return null
  try {
    const config = await getConfiguration(env)
    if (!config.serverMetadata().end_session_endpoint) return null
    return oidc.buildEndSessionUrl(config, {
      client_id: env.OIDC_CLIENT_ID!.trim(),
      post_logout_redirect_uri: `${appUrl(env)}/login?signed_out=1`,
    }).href
  } catch {
    return null
  }
}
