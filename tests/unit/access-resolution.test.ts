// How the request gate turns an identity into a role once users live in the
// database (lib/auth/resolve.ts, through authenticate()).

import { beforeEach, describe, expect, it } from 'vitest'
import { authenticate } from '@/lib/auth'
import { sealSession, sessionCookieName } from '@/lib/auth/session'
import { MemoryDirectory } from '../helpers/memory-directory'

const OIDC = { AUTH_PROVIDER: 'oidc', SESSION_SECRET: 's'.repeat(40), APP_URL: 'http://localhost:3000' }
const LOCAL = { APP_SECRET: 'a'.repeat(40), APP_URL: 'http://localhost:3000' }
const PROXY = { AUTH_PROVIDER: 'proxy-header' }

let dir: MemoryDirectory
beforeEach(() => {
  dir = new MemoryDirectory()
})

const cookieReq = (token: string, env: Record<string, string>) => ({
  headers: { get: () => null },
  cookie: (name: string) => (name === sessionCookieName(env) ? token : undefined),
})
const proxyReq = (email: string, groups = '') => ({
  headers: { get: (n: string) => (n === 'x-forwarded-email' ? email : n === 'x-forwarded-groups' ? groups : null) },
  cookie: () => undefined,
})
const session = (email: string, env: Record<string, string>, extra: { userId?: number } = {}) =>
  sealSession({ sub: extra.userId ? `user:${extra.userId}` : 'idp-sub', email, groups: [] }, env, extra)

describe('roles from the database', () => {
  it('refuses a disabled user, whatever the access lists say', async () => {
    dir.add({ email: 'admin@example.com', role: 'admin', status: 'disabled' })
    const env = { ...PROXY, ADMIN_EMAILS: 'admin@example.com' }
    expect(await authenticate(proxyReq('admin@example.com'), env, dir)).toMatchObject({ status: 'forbidden' })
  })

  it('refuses a session issued before the user’s sessions_valid_after', async () => {
    const u = dir.add({ email: 'v@example.com', role: 'viewer' })
    const token = await session('v@example.com', OIDC, { userId: u.id })
    expect(await authenticate(cookieReq(token, OIDC), OIDC, dir)).toMatchObject({ status: 'ok', session: { role: 'viewer', userId: u.id } })
    u.sessions_valid_after = new Date(Date.now() + 1000).toISOString()
    expect(await authenticate(cookieReq(token, OIDC), OIDC, dir)).toEqual({ status: 'unauthenticated' })
    // and an unreadable cut-off is not "no cut-off"
    u.sessions_valid_after = 'not a date'
    expect(await authenticate(cookieReq(token, OIDC), OIDC, dir)).toEqual({ status: 'unauthenticated' })
  })

  it('applies a role change on the next request', async () => {
    const u = dir.add({ email: 'p@example.com', role: 'viewer' })
    const r = proxyReq('p@example.com')
    expect(await authenticate(r, PROXY, dir)).toMatchObject({ session: { role: 'viewer' } })
    u.role = 'admin'
    expect(await authenticate(r, PROXY, dir)).toMatchObject({ session: { role: 'admin' } })
    u.status = 'disabled'
    expect(await authenticate(r, PROXY, dir)).toMatchObject({ status: 'forbidden' })
  })

  it('records someone no rule admits as a pending request, once, and refuses them', async () => {
    expect(await authenticate(proxyReq('new@elsewhere.test'), PROXY, dir)).toMatchObject({ status: 'forbidden' })
    expect(await authenticate(proxyReq('new@elsewhere.test'), PROXY, dir)).toMatchObject({ status: 'forbidden' })
    expect(dir.users).toMatchObject([{ email: 'new@elsewhere.test', status: 'pending' }])
    expect(dir.audits.map((a) => a.action)).toEqual(['access_requested'])
  })

  it('creates a rule-admitted person as active, and lets a pending one in once a rule admits them', async () => {
    await authenticate(proxyReq('later@example.com'), PROXY, dir)
    expect(dir.users[0].status).toBe('pending')
    const env = { ...PROXY, ALLOWED_EMAIL_DOMAINS: 'example.com' }
    expect(await authenticate(proxyReq('later@example.com'), env, dir)).toMatchObject({ status: 'ok', session: { role: 'viewer' } })
    expect(dir.users[0]).toMatchObject({ status: 'active', role_source: 'rule' })

    expect(await authenticate(proxyReq('fresh@example.com'), env, dir)).toMatchObject({ status: 'ok' })
    expect(dir.users[1]).toMatchObject({ email: 'fresh@example.com', status: 'active', role: 'viewer', role_source: 'rule' })
  })

  it('takes access away again when the rule that gave it is removed (as in 1.1.0)', async () => {
    const env = { ...PROXY, ADMIN_EMAILS: 'ops@example.com' }
    expect(await authenticate(proxyReq('ops@example.com'), env, dir)).toMatchObject({ session: { role: 'admin' } })
    expect(await authenticate(proxyReq('ops@example.com'), PROXY, dir)).toMatchObject({ status: 'forbidden' })
  })

  it('uses database rules for domains and groups', async () => {
    dir.rules = [
      { kind: 'email_domain', value: 'example.com', role: 'viewer' },
      { kind: 'group', value: 'dmarc-admins', role: 'admin' },
    ]
    expect(await authenticate(proxyReq('a@example.com'), PROXY, dir)).toMatchObject({ session: { role: 'viewer' } })
    expect(await authenticate(proxyReq('b@example.com', 'staff, DMARC-Admins'), PROXY, dir)).toMatchObject({ session: { role: 'admin' } })
    expect(await authenticate(proxyReq('c@lookalike-example.com'), PROXY, dir)).toMatchObject({ status: 'forbidden' })
  })

  it('gives the higher of the assigned role and the rules, and rules never make an owner', async () => {
    dir.add({ email: 'owner@example.com', role: 'owner' })
    dir.add({ email: 'viewer@example.com', role: 'viewer' })
    const env = { ...PROXY, ADMIN_EMAILS: 'owner@example.com,viewer@example.com' }
    expect(await authenticate(proxyReq('owner@example.com'), env, dir)).toMatchObject({ session: { role: 'owner' } })
    expect(await authenticate(proxyReq('viewer@example.com'), env, dir)).toMatchObject({ session: { role: 'admin' } })
  })

  it('does not accept a cookie for a user that is gone or whose address changed', async () => {
    const u = dir.add({ email: 'x@example.com', role: 'viewer' })
    const token = await session('x@example.com', OIDC, { userId: u.id })
    u.email = 'y@example.com'
    expect(await authenticate(cookieReq(token, OIDC), OIDC, dir)).toEqual({ status: 'unauthenticated' })
    dir.users = []
    expect(await authenticate(cookieReq(token, OIDC), OIDC, dir)).toEqual({ status: 'unauthenticated' })
  })
})

describe('sign-in managed in the app (AUTH_PROVIDER unset)', () => {
  it('serves only setup until an owner exists', async () => {
    dir.ownerExists = false
    expect(await authenticate(cookieReq('', LOCAL), LOCAL, dir)).toEqual({ status: 'setup_required' })
  })

  it('accepts only sessions issued to a user', async () => {
    const owner = dir.add({ email: 'owner@example.com', role: 'owner' })
    expect(await authenticate(cookieReq(await session('owner@example.com', LOCAL, { userId: owner.id }), LOCAL), LOCAL, dir)).toMatchObject({
      status: 'ok',
      session: { role: 'owner' },
    })
    expect(await authenticate(cookieReq(await session('owner@example.com', LOCAL), LOCAL), LOCAL, dir)).toEqual({ status: 'unauthenticated' })
  })

  it('needs APP_SECRET', async () => {
    await expect(authenticate(cookieReq('x', { APP_URL: 'http://localhost:3000' }), { APP_URL: 'http://localhost:3000' }, dir)).rejects.toThrow(/APP_SECRET/)
  })

  it('does not accept a cookie sealed under SESSION_SECRET once only APP_SECRET is set, or the reverse', async () => {
    const owner = dir.add({ email: 'owner@example.com', role: 'owner' })
    const withSession = { ...LOCAL, SESSION_SECRET: 'z'.repeat(40) }
    const token = await session('owner@example.com', withSession, { userId: owner.id })
    expect(await authenticate(cookieReq(token, withSession), withSession, dir)).toMatchObject({ status: 'ok' })
    expect(await authenticate(cookieReq(token, LOCAL), LOCAL, dir)).toEqual({ status: 'unauthenticated' })
  })
})

describe('AUTH_PROVIDER=none', () => {
  it('needs no database and grants everything (development only)', async () => {
    const env = { AUTH_PROVIDER: 'none' }
    expect(await authenticate(cookieReq('', env), env, dir)).toMatchObject({ status: 'ok', session: { role: 'owner', userId: null } })
  })
})
