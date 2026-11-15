import { describe, expect, it, vi } from 'vitest'
import {
  cookieOptions,
  safeReturnTo,
  sealLoginState,
  sealSession,
  sessionCookieName,
  unsealLoginState,
  unsealSession,
} from '@/lib/auth/session'

const env = { SESSION_SECRET: 'x'.repeat(40), APP_URL: 'https://dmarc.example.com', NODE_ENV: 'production' }
const identity = { sub: 'u1', email: 'a@example.com', name: 'A', groups: ['admins'] }

describe('session cookies', () => {
  it('round-trips an identity', async () => {
    const token = await sealSession(identity, env)
    expect(token.split('.')).toHaveLength(5) // compact JWE
    expect(token).not.toContain('example.com')
    expect(await unsealSession(token, env)).toEqual(identity)
  })

  it('rejects tampered, foreign and garbage tokens', async () => {
    const token = await sealSession(identity, env)
    const flipped = token.slice(0, -2) + (token.endsWith('A') ? 'B' : 'A') + token.slice(-1)
    expect(await unsealSession(flipped, env)).toBeNull()
    expect(await unsealSession(token, { ...env, SESSION_SECRET: 'y'.repeat(40) })).toBeNull()
    expect(await unsealSession('not-a-token', env)).toBeNull()
    expect(await unsealSession(undefined, env)).toBeNull()
  })

  it('does not accept a login-state cookie as a session (separate keys)', async () => {
    const login = await sealLoginState({ state: 's', nonce: 'n', codeVerifier: 'v', returnTo: '/' }, env)
    expect(await unsealSession(login, env)).toBeNull()
    const session = await sealSession(identity, env)
    expect(await unsealLoginState(session, env)).toBeNull()
    expect(await unsealLoginState(login, env)).toEqual({ state: 's', nonce: 'n', codeVerifier: 'v', returnTo: '/' })
  })

  it('expires', async () => {
    const short = { ...env, SESSION_MAX_AGE_HOURS: '1' }
    const token = await sealSession(identity, short)
    vi.useFakeTimers()
    try {
      vi.setSystemTime(Date.now() + 59 * 60 * 1000)
      expect(await unsealSession(token, short)).toEqual(identity)
      vi.setSystemTime(Date.now() + 2 * 60 * 1000)
      expect(await unsealSession(token, short)).toBeNull()
    } finally {
      vi.useRealTimers()
    }
  })

  it('refuses a short secret', async () => {
    await expect(sealSession(identity, { ...env, SESSION_SECRET: 'short' })).rejects.toThrow(/SESSION_SECRET/)
  })

  it('uses hardened cookie attributes over https', () => {
    expect(sessionCookieName(env)).toBe('__Host-dmarcscope_session')
    expect(cookieOptions(60, env)).toMatchObject({ httpOnly: true, secure: true, sameSite: 'lax', path: '/' })
    expect(sessionCookieName({ APP_URL: 'http://localhost:3000' })).toBe('dmarcscope_session')
  })
})

describe('safeReturnTo', () => {
  it('allows same-site paths', () => {
    expect(safeReturnTo('/issues?range=30d')).toBe('/issues?range=30d')
    expect(safeReturnTo('/domains/example.com')).toBe('/domains/example.com')
  })
  it('rejects open redirects and auth loops', () => {
    for (const bad of ['https://evil.test', '//evil.test', '/\\evil.test', 'javascript:alert(1)', '', null, '/login', '/auth/login', '/api/x', '/a\nb']) {
      expect(safeReturnTo(bad as string | null)).toBe('/')
    }
  })
})
