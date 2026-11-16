// Stateless, encrypted cookies (JWE, dir + A256GCM) for the built-in OIDC
// login. Nothing is stored server-side, so any number of replicas can serve
// the same user without shared session storage.
//
// Each purpose ("session", "login") gets its own key derived from
// SESSION_SECRET, so a login-state cookie can never be replayed as a session.

import { EncryptJWT, jwtDecrypt } from 'jose'
import { ConfigError, appUrl, envInt, type Env } from '../config'
import type { Identity } from './types'

type Purpose = 'session' | 'login'

const keyCache = new Map<string, Promise<Uint8Array>>()

function deriveKey(purpose: Purpose, env: Env): Promise<Uint8Array> {
  const secret = env.SESSION_SECRET || ''
  if (secret.length < 32) {
    throw new ConfigError('SESSION_SECRET must be set to at least 32 random characters (generate one with: openssl rand -base64 32).')
  }
  const cacheKey = `${purpose}:${secret}`
  let key = keyCache.get(cacheKey)
  if (!key) {
    key = (async () => {
      const enc = new TextEncoder()
      const base = await crypto.subtle.importKey('raw', enc.encode(secret), 'HKDF', false, ['deriveBits'])
      const bits = await crypto.subtle.deriveBits(
        { name: 'HKDF', hash: 'SHA-256', salt: enc.encode('dmarcscope'), info: enc.encode(`cookie:${purpose}`) },
        base,
        256
      )
      return new Uint8Array(bits)
    })()
    keyCache.set(cacheKey, key)
  }
  return key
}

async function seal(payload: Record<string, unknown>, purpose: Purpose, ttlSeconds: number, env: Env): Promise<string> {
  const key = await deriveKey(purpose, env)
  return new EncryptJWT(payload)
    .setProtectedHeader({ alg: 'dir', enc: 'A256GCM' })
    .setIssuedAt()
    .setExpirationTime(Math.floor(Date.now() / 1000) + ttlSeconds)
    .encrypt(key)
}

async function unseal(token: string | undefined, purpose: Purpose, env: Env): Promise<Record<string, unknown> | null> {
  if (!token) return null
  const key = await deriveKey(purpose, env)
  try {
    const { payload } = await jwtDecrypt(token, key, {
      keyManagementAlgorithms: ['dir'],
      contentEncryptionAlgorithms: ['A256GCM'],
    })
    return payload
  } catch {
    // expired, tampered with, or encrypted under a rotated secret
    return null
  }
}

// ---------- cookie attributes ----------

export function isSecureDeployment(env: Env = process.env): boolean {
  return appUrl(env).startsWith('https://')
}

// The __Host- prefix makes browsers refuse the cookie unless it is Secure,
// host-only and Path=/ — it cannot be set or overwritten from a subdomain.
export function sessionCookieName(env: Env = process.env): string {
  return `${isSecureDeployment(env) ? '__Host-' : ''}dmarcscope_session`
}

export function loginCookieName(env: Env = process.env): string {
  return `${isSecureDeployment(env) ? '__Host-' : ''}dmarcscope_login`
}

// Identity and group membership are captured at sign-in and live for this
// long, so it is also the longest a removal at the identity provider can take
// to reach this app. Capped at 7 days.
export function sessionTtlSeconds(env: Env = process.env): number {
  return envInt(env.SESSION_MAX_AGE_HOURS, 12, 1, 24 * 7) * 3600
}

// SESSION_NOT_BEFORE=<ISO timestamp>: sessions issued before that moment are
// rejected. Sessions are stateless, so this is the revocation lever: set it
// to "now" and everyone signed in earlier has to sign in again.
export function sessionNotBeforeSeconds(env: Env = process.env): number | null {
  const raw = env.SESSION_NOT_BEFORE?.trim()
  if (!raw) return null
  const ms = Date.parse(raw)
  if (Number.isNaN(ms)) {
    throw new ConfigError('SESSION_NOT_BEFORE must be an ISO timestamp, e.g. 2026-01-31T09:00:00Z.')
  }
  return Math.floor(ms / 1000)
}

export const LOGIN_TTL_SECONDS = 600

export function cookieOptions(maxAge: number, env: Env = process.env) {
  return {
    httpOnly: true,
    secure: isSecureDeployment(env),
    sameSite: 'lax' as const,
    path: '/',
    maxAge,
  }
}

// ---------- session ----------

export async function sealSession(identity: Identity, env: Env = process.env): Promise<string> {
  return seal(
    { sub: identity.sub, email: identity.email, name: identity.name, groups: identity.groups },
    'session',
    sessionTtlSeconds(env),
    env
  )
}

export async function unsealSession(token: string | undefined, env: Env = process.env): Promise<Identity | null> {
  const notBefore = sessionNotBeforeSeconds(env)
  const p = await unseal(token, 'session', env)
  if (!p || typeof p.sub !== 'string' || typeof p.email !== 'string') return null
  if (notBefore != null && (typeof p.iat !== 'number' || p.iat < notBefore)) return null
  return {
    sub: p.sub,
    email: p.email,
    name: typeof p.name === 'string' ? p.name : undefined,
    groups: Array.isArray(p.groups) ? p.groups.filter((g): g is string => typeof g === 'string') : [],
  }
}

// ---------- in-flight login state (PKCE verifier, state, nonce) ----------

export type LoginState = {
  state: string
  nonce: string
  codeVerifier: string
  returnTo: string
}

export async function sealLoginState(state: LoginState, env: Env = process.env): Promise<string> {
  return seal(state, 'login', LOGIN_TTL_SECONDS, env)
}

export async function unsealLoginState(token: string | undefined, env: Env = process.env): Promise<LoginState | null> {
  const p = await unseal(token, 'login', env)
  if (
    !p ||
    typeof p.state !== 'string' ||
    typeof p.nonce !== 'string' ||
    typeof p.codeVerifier !== 'string' ||
    typeof p.returnTo !== 'string'
  ) {
    return null
  }
  return { state: p.state, nonce: p.nonce, codeVerifier: p.codeVerifier, returnTo: p.returnTo }
}

// Only same-site relative paths are acceptable post-login destinations.
export function safeReturnTo(raw: string | null | undefined): string {
  if (!raw || !raw.startsWith('/') || raw.startsWith('//') || raw.includes('\\') || /[\x00-\x1f]/.test(raw)) {
    return '/'
  }
  if (raw.startsWith('/auth/') || raw.startsWith('/login') || raw.startsWith('/api/')) return '/'
  return raw
}
