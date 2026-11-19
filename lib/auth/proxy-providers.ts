// Authentication delegated to something in front of the app.
//
// proxy-jwt     The proxy signs an assertion (a JWT) into a request header and
//               we verify it against the proxy's published keys. This is how
//               Google Cloud IAP and Cloudflare Access work, and it stays safe
//               even if a request somehow reaches the app without going
//               through the proxy.
//
// proxy-header  The proxy passes the user's email in a plain header
//               (oauth2-proxy, nginx auth_request, Traefik ForwardAuth, ...).
//               Only safe when the app is unreachable except through the
//               proxy, so production use requires either a shared secret the
//               proxy injects or an explicit acknowledgement.

import { createRemoteJWKSet, jwtVerify, type JWTVerifyGetKey } from 'jose'
import { ConfigError, envBool, safeEqual, type Env } from '../config'
import { relevantGroups } from './authz'
import type { Identity } from './types'

type HeaderBag = { get(name: string): string | null }

// One address: something@something, no whitespace, commas or second "@".
const EMAIL_SHAPE = /^[^@\s,]+@[^@\s,]+$/

// ---------- proxy-jwt ----------

type JwtProxyConfig = {
  header: string
  jwksUrl: string
  issuer: string
  audience: string
  emailClaim: string
  groupsClaim: string
}

export function jwtProxyConfig(env: Env = process.env): JwtProxyConfig {
  const preset = (env.AUTH_PROXY_PRESET || '').trim().toLowerCase()
  const audience = env.AUTH_PROXY_AUDIENCE?.trim()
  let header = env.AUTH_PROXY_JWT_HEADER?.trim()
  let jwksUrl = env.AUTH_PROXY_JWKS_URL?.trim()
  let issuer = env.AUTH_PROXY_ISSUER?.trim()

  if (preset === 'gcp-iap') {
    header ||= 'x-goog-iap-jwt-assertion'
    jwksUrl ||= 'https://www.gstatic.com/iap/verify/public_key-jwk'
    issuer ||= 'https://cloud.google.com/iap'
  } else if (preset === 'cloudflare-access') {
    header ||= 'cf-access-jwt-assertion'
    if (!issuer) {
      throw new ConfigError('AUTH_PROXY_PRESET=cloudflare-access requires AUTH_PROXY_ISSUER=https://<team>.cloudflareaccess.com')
    }
    jwksUrl ||= `${issuer.replace(/\/$/, '')}/cdn-cgi/access/certs`
  } else if (preset) {
    throw new ConfigError(`Unknown AUTH_PROXY_PRESET "${preset}" (expected gcp-iap or cloudflare-access, or leave it unset).`)
  }

  if (!header || !jwksUrl || !issuer) {
    throw new ConfigError('AUTH_PROVIDER=proxy-jwt requires AUTH_PROXY_PRESET, or all of AUTH_PROXY_JWT_HEADER, AUTH_PROXY_JWKS_URL and AUTH_PROXY_ISSUER.')
  }
  if (!audience) {
    // Without an audience check, a token minted for any other application
    // behind the same proxy would be accepted here.
    throw new ConfigError('AUTH_PROVIDER=proxy-jwt requires AUTH_PROXY_AUDIENCE (the audience the proxy issues for this application).')
  }
  if (!jwksUrl.startsWith('https://') && !envBool(env.AUTH_PROXY_ALLOW_INSECURE_JWKS)) {
    throw new ConfigError('AUTH_PROXY_JWKS_URL must use https.')
  }
  return {
    header: header.toLowerCase(),
    jwksUrl,
    issuer,
    audience,
    emailClaim: env.AUTH_PROXY_EMAIL_CLAIM?.trim() || 'email',
    groupsClaim: env.AUTH_PROXY_GROUPS_CLAIM?.trim() || 'groups',
  }
}

const jwksCache = new Map<string, JWTVerifyGetKey>()

function jwksFor(url: string): JWTVerifyGetKey {
  let jwks = jwksCache.get(url)
  if (!jwks) {
    jwks = createRemoteJWKSet(new URL(url))
    jwksCache.set(url, jwks)
  }
  return jwks
}

export async function identityFromProxyJwt(headers: HeaderBag, env: Env = process.env, extraGroups: readonly string[] = []): Promise<Identity | null> {
  const cfg = jwtProxyConfig(env)
  const token = headers.get(cfg.header)
  if (!token) return null
  try {
    const { payload } = await jwtVerify(token, jwksFor(cfg.jwksUrl), {
      issuer: cfg.issuer,
      audience: cfg.audience,
      // Asymmetric signatures only: never accept a token "signed" with a
      // shared secret or with alg=none.
      algorithms: ['RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512', 'PS256', 'PS384', 'PS512', 'EdDSA'],
      clockTolerance: 30,
      // An assertion with no expiry would be valid forever if it leaked.
      requiredClaims: ['exp'],
    })
    const email = payload[cfg.emailClaim]
    if (typeof email !== 'string' || !EMAIL_SHAPE.test(email)) return null
    const rawGroups = payload[cfg.groupsClaim]
    const groups = Array.isArray(rawGroups) ? rawGroups.filter((g): g is string => typeof g === 'string') : []
    return {
      sub: typeof payload.sub === 'string' ? payload.sub : email,
      email: email.toLowerCase(),
      name: typeof payload.name === 'string' ? payload.name : undefined,
      groups: relevantGroups(groups, env, extraGroups),
    }
  } catch (err) {
    console.warn('[auth] proxy assertion rejected:', err instanceof Error ? err.message : String(err))
    return null
  }
}

// ---------- proxy-header ----------

export function identityFromProxyHeader(headers: HeaderBag, env: Env = process.env, extraGroups: readonly string[] = []): Identity | null {
  const secret = env.AUTH_PROXY_SHARED_SECRET
  if (secret) {
    if (secret.length < 16) {
      throw new ConfigError('AUTH_PROXY_SHARED_SECRET must be at least 16 characters.')
    }
    const secretHeader = (env.AUTH_PROXY_SECRET_HEADER?.trim() || 'x-proxy-secret').toLowerCase()
    const presented = headers.get(secretHeader)
    if (!presented || !safeEqual(presented, secret)) return null
  } else if (env.NODE_ENV === 'production' && !envBool(env.AUTH_PROXY_TRUST_NETWORK)) {
    throw new ConfigError(
      'AUTH_PROVIDER=proxy-header trusts a plain request header. Set AUTH_PROXY_SHARED_SECRET (a secret header your proxy adds), ' +
        'or set AUTH_PROXY_TRUST_NETWORK=true to confirm that this app can only be reached through the proxy.'
    )
  }

  const emailHeader = (env.AUTH_PROXY_EMAIL_HEADER?.trim() || 'x-forwarded-email').toLowerCase()
  const groupsHeader = (env.AUTH_PROXY_GROUPS_HEADER?.trim() || 'x-forwarded-groups').toLowerCase()
  const nameHeader = (env.AUTH_PROXY_NAME_HEADER?.trim() || 'x-forwarded-preferred-username').toLowerCase()

  const email = headers.get(emailHeader)?.trim().toLowerCase()
  if (!email || !EMAIL_SHAPE.test(email)) return null
  const groups = (headers.get(groupsHeader) || '')
    .split(',')
    .map((g) => g.trim())
    .filter(Boolean)
  return {
    sub: email,
    email,
    name: headers.get(nameHeader)?.trim() || undefined,
    groups: relevantGroups(groups, env, extraGroups),
  }
}
