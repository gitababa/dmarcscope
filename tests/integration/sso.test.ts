// Single sign-on configured in the panel, against PostgreSQL and a real
// (in-process) OpenID provider: a misconfigured connection can never be
// activated and never locks anyone out; switching providers leaves the
// owner's access alone.

import { NextRequest } from 'next/server'
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest'
import { hashPassword, newTotpSecret, encryptSecret } from '@/lib/crypto'
import { TEST_DATABASE_URL, createSchema } from '../helpers/db'
import { MockIdp } from '../helpers/mock-idp'

const SCHEMA = 'dmarcscope_sso_test'
const BASE = 'http://localhost:3000'
const APP_SECRET = 'sso-test-app-secret-0123456789-abcdefghijkl'
const OWNER_PASSWORD = 'owner-password-cobalt-heron-52'

describe.skipIf(!TEST_DATABASE_URL)('single sign-on from the panel', () => {
  let db: Awaited<ReturnType<typeof createSchema>>
  let idp: MockIdp
  let sso: typeof import('@/lib/sso')
  let testRoute: typeof import('@/app/auth/sso-test/route')
  let loginRoute: typeof import('@/app/auth/login/route')
  let callbackRoute: typeof import('@/app/auth/callback/route')
  let session: typeof import('@/lib/auth/session')
  let auth: typeof import('@/lib/auth')
  let pool: import('pg').Pool
  const ids: Record<string, number> = {}

  const OWNER = () => ({ userId: ids.owner, email: 'owner@example.com', ip: null, role: 'owner' as const })
  const ADMIN = () => ({ userId: ids.admin, email: 'admin@example.com', ip: null, role: 'admin' as const })
  const cookieOf = async (who: 'owner' | 'admin') =>
    session.sealSession({ sub: `user:${ids[who]}`, email: `${who}@example.com`, groups: [] }, process.env, { userId: ids[who] })

  const request = (path: string, cookies: Record<string, string> = {}) =>
    new NextRequest(path.startsWith('http') ? path : `${BASE}${path}`, {
      headers: { cookie: Object.entries(cookies).map(([k, v]) => `${k}=${v}`).join('; '), 'x-forwarded-for': '192.0.2.50' },
    })
  const setCookies = (res: Response) =>
    Object.fromEntries(res.headers.getSetCookie().map((c) => c.split(';')[0]).map((p) => [p.slice(0, p.indexOf('=')), p.slice(p.indexOf('=') + 1)]))
  const draft = () => sso.getConnection(pool, 'draft')

  // The whole test flow, as the owner's browser would run it.
  async function runTest(as: 'owner' | 'admin' = 'owner', callbackAs: 'owner' | 'admin' | null = as) {
    const start = await testRoute.GET(request('/auth/sso-test', { dmarcscope_session: await cookieOf(as) }))
    const location = start.headers.get('location') || ''
    if (start.status === 404 || !location.startsWith(idp.issuer)) return { start, callback: null }
    const login = setCookies(start).dmarcscope_login
    const authorize = await fetch(location, { redirect: 'manual' })
    const cookies: Record<string, string> = { dmarcscope_login: login }
    if (callbackAs) cookies.dmarcscope_session = await cookieOf(callbackAs)
    const callback = await callbackRoute.GET(request(authorize.headers.get('location')!, cookies))
    return { start, callback }
  }

  const goodDraft = () => ({
    preset: 'generic',
    issuer: idp.issuer,
    clientId: idp.clientId,
    clientSecret: idp.clientSecret,
    clearSecret: false,
    scopes: 'openid email profile',
    emailClaim: 'email',
    groupsClaim: 'groups',
    requiredClaims: '',
    buttonLabel: 'Test IdP',
  })

  beforeAll(async () => {
    db = await createSchema(SCHEMA)
    idp = await new MockIdp().start()
    idp.redirectUris = [`${BASE}/auth/callback`]
    for (const k of ['AUTH_PROVIDER', 'SESSION_SECRET', 'AUTH_ENFORCE_SSO', 'AUTH_LOCAL_SIGNIN_NON_OWNERS', 'CLIENT_IP_HEADER']) delete process.env[k]
    Object.assign(process.env, { DATABASE_URL: db.url, APP_SECRET, APP_URL: BASE, OIDC_ALLOW_INSECURE_ISSUER: 'true', SETTINGS_CACHE_SECONDS: '0' })
    vi.spyOn(console, 'log').mockImplementation(() => {})
    vi.spyOn(console, 'error').mockImplementation(() => {})
    sso = await import('@/lib/sso')
    testRoute = await import('@/app/auth/sso-test/route')
    loginRoute = await import('@/app/auth/login/route')
    callbackRoute = await import('@/app/auth/callback/route')
    session = await import('@/lib/auth/session')
    auth = await import('@/lib/auth')
    pool = (await import('@/lib/db')).getPool()
  })
  afterAll(async () => {
    vi.restoreAllMocks()
    await idp?.stop()
    const { closePool } = await import('@/lib/db')
    await closePool()
    await db?.drop()
  })

  beforeEach(async () => {
    await db.admin.query(`TRUNCATE users, sso_connections, settings RESTART IDENTITY CASCADE; UPDATE config_version SET version = version + 1`)
    const owner = await db.admin.query(
      `INSERT INTO users (email, role, role_source, status, source, password_hash, totp_confirmed_at) VALUES ('owner@example.com', 'owner', 'assigned', 'active', 'local', $1, NOW()) RETURNING id`,
      [await hashPassword(OWNER_PASSWORD)]
    )
    ids.owner = Number(owner.rows[0].id)
    await db.admin.query(`UPDATE users SET totp_secret = $2 WHERE id = $1`, [ids.owner, encryptSecret('totp', `user:${ids.owner}`, newTotpSecret())])
    const admin = await db.admin.query(`INSERT INTO users (email, role, role_source, status, source) VALUES ('admin@example.com', 'admin', 'assigned', 'active', 'oidc') RETURNING id`)
    ids.admin = Number(admin.rows[0].id)
    idp.clientSecret = 'mock-idp-client-secret'
    idp.redirectUris = [`${BASE}/auth/callback`]
    idp.nextUser = { sub: 'owner-at-idp', email: 'owner@example.com', email_verified: true, name: 'Owner' }
  })

  const refused = async (p: Promise<unknown>, code: string) => {
    await expect(p).rejects.toMatchObject({ name: 'SsoRefusal', code })
  }

  it('is the owner’s alone: admins cannot edit, test or activate', async () => {
    await refused(sso.startDraft(pool, ADMIN(), 'generic'), 'not_allowed')
    await sso.startDraft(pool, OWNER(), 'generic')
    await refused(sso.saveDraft(pool, ADMIN(), goodDraft()), 'not_allowed')
    await refused(sso.activateDraft(pool, ADMIN()), 'not_allowed')
    await refused(sso.discardDraft(pool, ADMIN()), 'not_allowed')
    const { start } = await runTest('admin')
    expect(start.status).toBe(404)
    const anonymous = await testRoute.GET(request('/auth/sso-test'))
    expect(anonymous.status).toBe(404)
    const refusals = (await db.admin.query(`SELECT detail FROM audit_log WHERE action = 'action_refused'`)).rows
    expect(refusals.length).toBeGreaterThanOrEqual(6)
  })

  it('validates the draft', async () => {
    await sso.startDraft(pool, OWNER(), 'entra')
    const d = await draft()
    expect(d).toMatchObject({ preset: 'entra', email_claim: 'preferred_username', issuer: 'https://login.microsoftonline.com/TENANT-ID/v2.0' })
    // the placeholder has to be filled in
    await refused(sso.saveDraft(pool, OWNER(), { ...goodDraft(), issuer: d!.issuer }), 'invalid')
    await refused(sso.saveDraft(pool, OWNER(), { ...goodDraft(), issuer: 'ftp://idp.example' }), 'invalid')
    await refused(sso.saveDraft(pool, OWNER(), { ...goodDraft(), scopes: 'email profile' }), 'invalid')
    await refused(sso.saveDraft(pool, OWNER(), { ...goodDraft(), requiredClaims: 'hd' }), 'invalid')
    await refused(sso.saveDraft(pool, OWNER(), { ...goodDraft(), emailClaim: 'e mail' }), 'invalid')
    await refused(sso.saveDraft(pool, OWNER(), { ...goodDraft(), clientId: 'has space' }), 'invalid')
    expect((await draft())!.revision).toBe(1)
  })

  it('never activates an untested draft, and saving changes nothing for anyone', async () => {
    await sso.startDraft(pool, OWNER(), 'generic')
    await sso.saveDraft(pool, OWNER(), goodDraft())
    await refused(sso.activateDraft(pool, OWNER()), 'not_tested')
    expect(await sso.getConnection(pool, 'active')).toBeNull()
    const start = await loginRoute.GET(request('/auth/login'))
    expect(start.headers.get('location')).toBe(`${BASE}/login`)
  })

  it('cannot activate with an unreachable issuer', async () => {
    await sso.startDraft(pool, OWNER(), 'generic')
    await sso.saveDraft(pool, OWNER(), { ...goodDraft(), issuer: 'http://127.0.0.1:9' })
    const { start } = await runTest()
    expect(start.headers.get('location')).toBe(`${BASE}/admin/sso/test`)
    expect((await draft())!.last_test).toMatchObject({ ok: false, error: { code: 'discovery' } })
    await refused(sso.activateDraft(pool, OWNER()), 'test_failed')
  })

  it('cannot activate with a wrong client secret', async () => {
    await sso.startDraft(pool, OWNER(), 'generic')
    await sso.saveDraft(pool, OWNER(), { ...goodDraft(), clientSecret: 'not-the-secret' })
    const { callback } = await runTest()
    expect(callback!.headers.get('location')).toBe(`${BASE}/admin/sso/test`)
    expect((await draft())!.last_test).toMatchObject({ ok: false, error: { code: 'exchange' } })
    await refused(sso.activateDraft(pool, OWNER()), 'test_failed')
  })

  it('cannot activate when the redirect URI is not registered with the provider', async () => {
    idp.redirectUris = ['https://elsewhere.example/auth/callback']
    await sso.startDraft(pool, OWNER(), 'generic')
    await sso.saveDraft(pool, OWNER(), goodDraft())
    await runTest()
    expect((await draft())!.last_test).toMatchObject({ ok: false, error: { code: 'provider', message: expect.stringContaining('redirect_uri_mismatch') } })
    await refused(sso.activateDraft(pool, OWNER()), 'test_failed')
  })

  it('cannot activate when the provider does not verify the address or a required claim is missing', async () => {
    await sso.startDraft(pool, OWNER(), 'generic')
    await sso.saveDraft(pool, OWNER(), goodDraft())
    idp.nextUser = { sub: 'x', email: 'owner@example.com' }
    await runTest()
    expect((await draft())!.last_test).toMatchObject({ ok: false, error: { code: 'unverified_email' } })

    await sso.saveDraft(pool, OWNER(), { ...goodDraft(), requiredClaims: 'hd=example.com' })
    idp.nextUser = { sub: 'x', email: 'owner@example.com', email_verified: true }
    await runTest()
    expect((await draft())!.last_test).toMatchObject({ ok: false, error: { code: 'wrong_account' } })
    await refused(sso.activateDraft(pool, OWNER()), 'test_failed')
  })

  it('activates only a passed test of the current revision, less than a day old', async () => {
    await sso.startDraft(pool, OWNER(), 'generic')
    await sso.saveDraft(pool, OWNER(), goodDraft())
    const { callback } = await runTest()
    // a test issues no session
    expect(Object.keys(setCookies(callback!))).not.toContain('dmarcscope_session')
    expect((await draft())!.last_test).toMatchObject({
      ok: true,
      identity: { email: 'owner@example.com' },
      admission: { role: 'owner', via: 'existing user' },
      claims: { email: 'owner@example.com', email_verified: true },
    })

    // edited after the test: the test no longer counts
    await sso.saveDraft(pool, OWNER(), { ...goodDraft(), buttonLabel: 'Changed' })
    await refused(sso.activateDraft(pool, OWNER()), 'not_tested')
    await runTest()
    // too old
    await db.admin.query(`UPDATE sso_connections SET last_test = jsonb_set(last_test, '{at}', to_jsonb((NOW() - INTERVAL '25 hours')::text)) WHERE state = 'draft'`)
    await refused(sso.activateDraft(pool, OWNER()), 'test_stale')
    await runTest()
    await sso.activateDraft(pool, OWNER())
    expect(await sso.getConnection(pool, 'active')).toMatchObject({ issuer: idp.issuer, button_label: 'Changed' })
    expect(await draft()).toBeNull()
    expect((await db.admin.query(`SELECT action FROM audit_log WHERE action = 'sso_activated'`)).rows).toHaveLength(1)
  })

  it('records a test only for the owner who started it, and never creates users', async () => {
    await sso.startDraft(pool, OWNER(), 'generic')
    await sso.saveDraft(pool, OWNER(), goodDraft())
    idp.nextUser = { sub: 'stranger', email: 'stranger@elsewhere.test', email_verified: true }
    await runTest('owner', 'admin')
    expect((await draft())!.last_test).toBeNull()
    await runTest('owner', null)
    expect((await draft())!.last_test).toBeNull()
    await runTest('owner', 'owner')
    expect((await draft())!.last_test).toMatchObject({ ok: true, admission: { role: null, via: 'none' } })
    expect((await db.admin.query(`SELECT COUNT(*)::int AS n FROM users WHERE email = 'stranger@elsewhere.test'`)).rows[0].n).toBe(0)
  })

  async function activateGood(overrides: Partial<ReturnType<typeof goodDraft>> = {}) {
    await sso.startDraft(pool, OWNER(), 'generic')
    await sso.saveDraft(pool, OWNER(), { ...goodDraft(), ...overrides })
    idp.nextUser = { sub: 'owner-at-idp', email: 'owner@example.com', email_verified: true }
    await runTest()
    await sso.activateDraft(pool, OWNER())
  }

  async function signInWithSso(user: Record<string, unknown>) {
    idp.nextUser = user as never
    const start = await loginRoute.GET(request('/auth/login'))
    const location = start.headers.get('location') || ''
    if (!location.startsWith(idp.issuer)) return { location, cookies: {} as Record<string, string> }
    const authorize = await fetch(location, { redirect: 'manual' })
    const res = await callbackRoute.GET(request(authorize.headers.get('location')!, { dmarcscope_login: setCookies(start).dmarcscope_login }))
    return { location: res.headers.get('location'), cookies: setCookies(res) }
  }

  it('signs people in with the active connection, recording newcomers as requests', async () => {
    await activateGood()
    await db.admin.query(`INSERT INTO access_rules (kind, value, role) VALUES ('email_domain', 'example.com', 'viewer'); UPDATE config_version SET version = version + 1`)
    const member = await signInWithSso({ sub: 'm', email: 'member@example.com', email_verified: true })
    expect(member.location).toBe(`${BASE}/`)
    const req = { headers: new Headers(), cookie: (n: string) => (n === 'dmarcscope_session' ? member.cookies.dmarcscope_session : undefined) }
    expect(await auth.authenticate(req)).toMatchObject({ status: 'ok', session: { role: 'viewer' } })

    const stranger = await signInWithSso({ sub: 's', email: 'stranger@elsewhere.test', email_verified: true })
    expect(stranger.location).toBe(`${BASE}/denied`)
    const sreq = { headers: new Headers(), cookie: (n: string) => (n === 'dmarcscope_session' ? stranger.cookies.dmarcscope_session : undefined) }
    expect(await auth.authenticate(sreq)).toMatchObject({ status: 'forbidden' })
    expect((await db.admin.query(`SELECT status, source FROM users WHERE email = 'stranger@elsewhere.test'`)).rows[0]).toEqual({ status: 'pending', source: 'oidc' })
  })

  it('switching providers leaves the owner’s session and password sign-in alone', async () => {
    const ownerCookie = await cookieOf('owner')
    const ownerReq = { headers: new Headers(), cookie: (n: string) => (n === 'dmarcscope_session' ? ownerCookie : undefined) }
    await activateGood()
    expect(await auth.authenticate(ownerReq)).toMatchObject({ status: 'ok', session: { role: 'owner' } })

    // a second provider replaces the first
    const second = await new MockIdp().start()
    second.redirectUris = [`${BASE}/auth/callback`]
    try {
      await sso.startDraft(pool, OWNER(), 'generic')
      await sso.saveDraft(pool, OWNER(), { ...goodDraft(), issuer: second.issuer, clientId: second.clientId, clientSecret: second.clientSecret })
      second.nextUser = { sub: 'other-sub', email: 'owner@example.com', email_verified: true }
      const old = idp
      idp = second
      await runTest()
      idp = old
      await sso.activateDraft(pool, OWNER())
      expect((await sso.getConnection(pool, 'active'))!.issuer).toBe(second.issuer)
    } finally {
      await second.stop()
    }
    expect(await auth.authenticate(ownerReq)).toMatchObject({ status: 'ok', session: { role: 'owner', userId: ids.owner } })
    const { checkPassword } = await import('@/lib/auth/local')
    expect(await checkPassword(pool, 'owner@example.com', OWNER_PASSWORD, '192.0.2.1')).toMatchObject({ ok: true })
  })

  it('a connection that breaks after activation only breaks its own button', async () => {
    await activateGood()
    idp.clientSecret = 'rotated-at-the-provider'
    const broken = await signInWithSso({ sub: 'm', email: 'member@example.com', email_verified: true })
    expect(broken.location).toBe(`${BASE}/login?error=failed`)
    const { checkPassword } = await import('@/lib/auth/local')
    expect(await checkPassword(pool, 'owner@example.com', OWNER_PASSWORD, '192.0.2.2')).toMatchObject({ ok: true })
    await sso.deactivate(pool, OWNER())
    expect((await loginRoute.GET(request('/auth/login'))).headers.get('location')).toBe(`${BASE}/login`)
    await refused(sso.deactivate(pool, OWNER()), 'no_active')
  })

  it('applies the password switches to everyone but the owner', async () => {
    const { checkPassword } = await import('@/lib/auth/local')
    const store = (await import('@/lib/settings')).configStore()
    // a former owner, now admin, still has a password and TOTP
    await db.admin.query(
      `UPDATE users SET password_hash = (SELECT password_hash FROM users WHERE id = $2), totp_confirmed_at = NOW(), totp_secret = 'x' WHERE id = $1`,
      [ids.admin, ids.owner]
    )
    const former = () => checkPassword(pool, 'admin@example.com', OWNER_PASSWORD, null)
    expect(await former()).toMatchObject({ ok: false, reason: 'invalid' }) // off by default
    await store.write('auth.local_signin_non_owners', 'true', OWNER())
    await db.admin.query(`UPDATE users SET failed_logins = 0, locked_until = NULL`)
    expect(await former()).toMatchObject({ ok: true })
    // requiring SSO without an active connection changes nothing...
    await store.write('auth.enforce_sso', 'true', OWNER())
    expect(await former()).toMatchObject({ ok: true })
    // ...with one, it refuses non-owners, never the owner
    await activateGood()
    expect(await former()).toMatchObject({ ok: false, reason: 'invalid' })
    expect(await checkPassword(pool, 'owner@example.com', OWNER_PASSWORD, null)).toMatchObject({ ok: true })
  })

  it('keeps the client secret encrypted and out of the audit log and the page data', async () => {
    await activateGood()
    const rows = JSON.stringify((await db.admin.query(`SELECT * FROM sso_connections`)).rows)
    const audit = JSON.stringify((await db.admin.query(`SELECT * FROM audit_log`)).rows)
    expect(rows).not.toContain(idp.clientSecret)
    expect(audit).not.toContain(idp.clientSecret)
    const { configStore } = await import('@/lib/settings')
    expect(JSON.stringify(await configStore().snapshot())).not.toContain(idp.clientSecret)
  })
})
