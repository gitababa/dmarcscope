// The request gate itself: what an unauthenticated, unauthorized or
// misconfigured request gets back, for pages and for /api.

import { NextRequest } from 'next/server'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { setDirectoryForTests } from '@/lib/auth/directory'
import { sealSession, sessionCookieName } from '@/lib/auth/session'
import { proxy } from '@/proxy'
import { MemoryDirectory } from '../helpers/memory-directory'

const OIDC = {
  NODE_ENV: 'production',
  AUTH_PROVIDER: 'oidc',
  SESSION_SECRET: 's'.repeat(40),
  APP_URL: 'https://dmarc.example.com',
  ALLOWED_EMAILS: 'viewer@example.com',
}
const KEYS = [...Object.keys(OIDC), 'AUTH_ALLOW_INSECURE_NONE', 'AUTH_PROXY_SHARED_SECRET', 'OIDC_LOGOUT_AT_IDP']
const saved: Record<string, string | undefined> = {}

function setEnv(env: Record<string, string>) {
  for (const k of KEYS) delete process.env[k]
  Object.assign(process.env, env)
}

let dir = new MemoryDirectory()

beforeEach(() => {
  dir = new MemoryDirectory()
  setDirectoryForTests(dir)
  for (const k of KEYS) saved[k] = process.env[k]
  vi.spyOn(console, 'error').mockImplementation(() => {})
})
afterEach(() => {
  for (const k of KEYS) {
    if (saved[k] === undefined) delete process.env[k]
    else process.env[k] = saved[k]
  }
  vi.restoreAllMocks()
  setDirectoryForTests(null)
})

// The app listens on an internal address; the public one is APP_URL.
const request = (path: string, headers: Record<string, string> = {}) =>
  new NextRequest(`http://0.0.0.0:3000${path}`, { headers })

const withSession = async (email: string) => ({
  cookie: `${sessionCookieName(OIDC)}=${await sealSession({ sub: 'u', email, groups: [] }, OIDC)}`,
})

describe('proxy (request gate)', () => {
  it('sends anonymous page requests to the login page on the public URL', async () => {
    setEnv(OIDC)
    const res = await proxy(request('/issues?range=30d'))
    expect(res.status).toBe(307)
    expect(res.headers.get('location')).toBe('https://dmarc.example.com/login?returnTo=%2Fissues%3Frange%3D30d')
    expect((await proxy(request('/'))).headers.get('location')).toBe('https://dmarc.example.com/login')
  })

  it('answers anonymous API requests with 401 JSON, never a redirect', async () => {
    setEnv(OIDC)
    const res = await proxy(request('/api/anything'))
    expect(res.status).toBe(401)
    expect(await res.json()).toEqual({ ok: false, error: 'unauthenticated' })
  })

  it('lets an authorized session through with a nonce-based CSP', async () => {
    setEnv(OIDC)
    const res = await proxy(request('/issues', await withSession('viewer@example.com')))
    expect(res.status).toBe(200)
    expect(res.headers.get('location')).toBeNull()
    const csp = res.headers.get('content-security-policy')!
    expect(csp).toMatch(/script-src 'self' 'nonce-[A-Za-z0-9+/=]+' 'strict-dynamic'/)
    expect(csp).not.toContain('unsafe-eval')
    expect(csp).toContain(`frame-ancestors 'none'`)
    expect(csp).toContain(`form-action 'self'`)
  })

  it('refuses a signed-in user who is on no list', async () => {
    setEnv(OIDC)
    const stranger = await withSession('stranger@elsewhere.test')
    const page = await proxy(request('/', stranger))
    expect(page.headers.get('location')).toBe('https://dmarc.example.com/denied')
    expect((await proxy(request('/api/x', stranger))).status).toBe(403)
  })

  it('leaves only the documented paths open', async () => {
    setEnv(OIDC)
    for (const path of ['/login', '/denied', '/auth/login', '/auth/callback', '/api/healthz', '/api/readyz', '/api/cron/dns-check', '/api/cron/status']) {
      expect((await proxy(request(path))).status, path).toBe(200)
    }
    for (const path of ['/', '/issues', '/domains/example.com', '/api', '/api/healthz/x', '/api/cronx', '/loginx', '/authx/login']) {
      expect((await proxy(request(path))).status, path).not.toBe(200)
    }
  })

  it('does not tell an anonymous visitor what is misconfigured', async () => {
    setEnv({ NODE_ENV: 'production', AUTH_PROVIDER: 'none' })
    const page = await proxy(request('/'))
    expect(page.status).toBe(500)
    const text = await page.text()
    expect(text).toMatch(/configuration error/i)
    expect(text).not.toMatch(/AUTH_|none/)
    const api = await proxy(request('/api/x'))
    expect(api.status).toBe(500)
    expect(await api.json()).toEqual({ ok: false, error: 'server_configuration' })
    expect(console.error).toHaveBeenCalledWith(expect.stringContaining('AUTH_PROVIDER=none'))
  })

  it('ignores a forged identity header unless the proxy secret is present', async () => {
    setEnv({ NODE_ENV: 'production', AUTH_PROVIDER: 'proxy-header', AUTH_PROXY_SHARED_SECRET: 'p'.repeat(24), ALLOWED_EMAILS: 'viewer@example.com', APP_URL: OIDC.APP_URL })
    const forged = await proxy(request('/', { 'x-forwarded-email': 'viewer@example.com' }))
    expect(forged.headers.get('location')).toBe('https://dmarc.example.com/denied')
    const real = await proxy(request('/', { 'x-forwarded-email': 'viewer@example.com', 'x-proxy-secret': 'p'.repeat(24) }))
    expect(real.status).toBe(200)
  })
})
