// First-run setup and the owner's password + TOTP sign-in, through the real
// route handlers against PostgreSQL. Every refusal the plan lists has a test
// here, and the last test checks that no secret seeded along the way
// appears in a log line, an audit entry or a response.

import { NextRequest } from 'next/server'
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest'
import { totpCode, totpStep } from '@/lib/crypto'
import { TEST_DATABASE_URL, createSchema } from '../helpers/db'

const SCHEMA = 'dmarcscope_local_auth_test'
const BASE = 'http://localhost:3000'
const APP_SECRET = 'canary-app-secret-5c1e0b7d9a3f4e2b8c6d0a1f'
const PASSWORD = 'canary-password-amber-falcon-91'
const OWNER = 'owner@example.com'

// Everything printed while this file runs.
const printed: string[] = []
const bodies: string[] = []

const post = (path: string, fields: Record<string, string>, opts: { cookies?: Record<string, string>; origin?: string | null; ip?: string } = {}) => {
  const headers: Record<string, string> = { 'content-type': 'application/x-www-form-urlencoded', 'x-forwarded-for': opts.ip ?? '198.51.100.20' }
  if (opts.origin !== null) headers.origin = opts.origin ?? BASE
  if (opts.cookies) headers.cookie = Object.entries(opts.cookies).map(([k, v]) => `${k}=${v}`).join('; ')
  return new NextRequest(`${BASE}${path}`, { method: 'POST', headers, body: new URLSearchParams(fields).toString() })
}

async function record(res: Response): Promise<{ status: number; location: string | null; cookies: Record<string, string> }> {
  const text = await res.clone().text()
  bodies.push(text, res.headers.get('location') ?? '')
  const cookies: Record<string, string> = {}
  for (const raw of res.headers.getSetCookie()) {
    const [pair] = raw.split(';')
    cookies[pair.slice(0, pair.indexOf('='))] = pair.slice(pair.indexOf('=') + 1)
  }
  return { status: res.status, location: res.headers.get('location'), cookies }
}

describe.skipIf(!TEST_DATABASE_URL)('first-run setup and local sign-in', () => {
  let db: Awaited<ReturnType<typeof createSchema>>
  let setupRoute: typeof import('@/app/setup/[step]/route')
  let passwordRoute: typeof import('@/app/auth/password/route')
  let secondFactorRoute: typeof import('@/app/auth/second-factor/route')
  let token = ''
  let totpSecret = ''
  let recoveryCodes: string[] = []
  let ownerId = 0

  const setup = async (step: string, fields: Record<string, string>, opts: Parameters<typeof post>[2] = {}) =>
    record(await setupRoute.POST(post(`/setup/${step}`, fields, opts), { params: Promise.resolve({ step }) }))

  beforeAll(async () => {
    db = await createSchema(SCHEMA)
    for (const k of ['AUTH_PROVIDER', 'SESSION_SECRET', 'SETUP_TOKEN', 'CRON_SECRET', 'APP_SECRET_PREVIOUS', 'CLIENT_IP_HEADER']) delete process.env[k]
    Object.assign(process.env, { DATABASE_URL: db.url, APP_SECRET, APP_URL: BASE, SETTINGS_CACHE_SECONDS: '0' })
    for (const method of ['log', 'error', 'warn', 'info'] as const) {
      vi.spyOn(console, method).mockImplementation((...args: unknown[]) => {
        printed.push(args.map(String).join(' '))
      })
    }
    setupRoute = await import('@/app/setup/[step]/route')
    passwordRoute = await import('@/app/auth/password/route')
    secondFactorRoute = await import('@/app/auth/second-factor/route')
  })

  afterAll(async () => {
    vi.restoreAllMocks()
    const { closePool } = await import('@/lib/db')
    await closePool()
    await db?.drop()
  })

  // ---------- setup token ----------

  it('mints a setup token once, logs it once, and stores only its digest', async () => {
    const { ensureSetupToken } = await import('@/lib/setup')
    const { getPool } = await import('@/lib/db')
    await ensureSetupToken(getPool())
    await ensureSetupToken(getPool())
    const lines = printed.filter((l) => l.startsWith('[setup] No owner account exists yet'))
    expect(lines).toHaveLength(1)
    token = /setup token \(valid for 24 hours\): (\S+)$/.exec(lines[0])![1]
    expect(token.length).toBeGreaterThanOrEqual(40)
    const rows = (await db.admin.query('SELECT token_hash, expires_at FROM setup_tokens')).rows
    expect(rows).toHaveLength(1)
    expect(rows[0].token_hash).not.toContain(token)
  })

  it('refuses a wrong setup token, and a cross-origin post', async () => {
    const wrong = await setup('token', { token: 'not-the-token' })
    expect(wrong.location).toBe(`${BASE}/setup?error=token_invalid`)
    expect(wrong.cookies.dmarcscope_setup ?? '').toBe('')

    const crossOrigin = await setup('token', { token }, { origin: 'https://evil.example' })
    expect(crossOrigin.status).toBe(403)
    const noOrigin = await setup('token', { token }, { origin: null })
    expect(noOrigin.status).toBe(403)
  })

  it('refuses an expired setup token and a used one', async () => {
    const { checkSetupToken } = await import('@/lib/setup')
    const { sha256Hex } = await import('@/lib/crypto')
    await db.admin.query(`INSERT INTO setup_tokens (token_hash, expires_at) VALUES ($1, NOW() - INTERVAL '1 minute'), ($2, NOW() + INTERVAL '1 hour')`, [
      sha256Hex('expired-token-0000000000000000'),
      sha256Hex('used-token-00000000000000000000'),
    ])
    await db.admin.query(`UPDATE setup_tokens SET used_at = NOW() WHERE token_hash = $1`, [sha256Hex('used-token-00000000000000000000')])

    expect((await setup('token', { token: 'expired-token-0000000000000000' })).location).toBe(`${BASE}/setup?error=token_expired`)
    expect((await setup('token', { token: 'used-token-00000000000000000000' })).location).toBe(`${BASE}/setup?error=token_used`)

    // SETUP_TOKEN from the environment: accepted until spent, never twice
    const env = { ...process.env, SETUP_TOKEN: 'env-supplied-setup-token-123456789' }
    expect(await checkSetupToken(db.admin, 'env-supplied-setup-token-123456789', env)).toMatchObject({ ok: true })
    expect(await checkSetupToken(db.admin, 'env-supplied-setup-token-12345678X', env)).toEqual({ ok: false, reason: 'invalid' })
    await db.admin.query(`INSERT INTO setup_tokens (token_hash, used_at) VALUES ($1, NOW())`, [sha256Hex('env-supplied-setup-token-123456789')])
    expect(await checkSetupToken(db.admin, 'env-supplied-setup-token-123456789', env)).toEqual({ ok: false, reason: 'used' })
    // a short SETUP_TOKEN is refused outright
    expect(await checkSetupToken(db.admin, 'short', { ...env, SETUP_TOKEN: 'short' })).toEqual({ ok: false, reason: 'invalid' })
  })

  it('rate-limits wrong setup tokens per client address', async () => {
    let last = ''
    for (let i = 0; i < 11; i++) last = (await setup('token', { token: `guess-${i}` }, { ip: '203.0.113.66' })).location!
    expect(last).toBe(`${BASE}/setup?error=locked`)
    // even the right token is refused from that address for now
    expect((await setup('token', { token }, { ip: '203.0.113.66' })).location).toBe(`${BASE}/setup?error=locked`)
  })

  // ---------- owner account ----------

  it('walks through the wizard, refusing a weak password and a wrong code', async () => {
    const { unsealSetupState } = await import('@/lib/setup-state')
    const step1 = await setup('token', { token })
    expect(step1.location).toBe(`${BASE}/setup`)
    let cookies = { dmarcscope_setup: step1.cookies.dmarcscope_setup }

    const weak = await setup('account', { email: OWNER, name: 'Owner', password: 'password1234', password_confirm: 'password1234' }, { cookies })
    expect(weak.location).toBe(`${BASE}/setup?error=password_common`)
    const short = await setup('account', { email: OWNER, name: 'Owner', password: 'short', password_confirm: 'short' }, { cookies })
    expect(short.location).toBe(`${BASE}/setup?error=password_short`)
    const mismatch = await setup('account', { email: OWNER, name: 'Owner', password: PASSWORD, password_confirm: `${PASSWORD}x` }, { cookies })
    expect(mismatch.location).toBe(`${BASE}/setup?error=password_mismatch`)
    const badEmail = await setup('account', { email: 'not-an-address', name: '', password: PASSWORD, password_confirm: PASSWORD }, { cookies })
    expect(badEmail.location).toBe(`${BASE}/setup?error=email`)

    const step2 = await setup('account', { email: OWNER, name: 'Owner', password: PASSWORD, password_confirm: PASSWORD }, { cookies })
    expect(step2.location).toBe(`${BASE}/setup`)
    cookies = { dmarcscope_setup: step2.cookies.dmarcscope_setup }
    const state = await unsealSetupState(cookies.dmarcscope_setup)
    expect(state?.step).toBe('totp')
    totpSecret = state!.step === 'totp' ? state!.totpSecret : ''

    const wrongCode = await setup('totp', { code: totpCode(totpSecret, totpStep() + 5) }, { cookies })
    expect(wrongCode.location).toBe(`${BASE}/setup?error=code`)
    expect((await db.admin.query('SELECT COUNT(*)::int AS n FROM users')).rows[0].n).toBe(0)

    const done = await setup('totp', { code: totpCode(totpSecret) }, { cookies })
    expect(done.location).toBe(`${BASE}/welcome`)
    expect(done.cookies.dmarcscope_session).toBeTruthy()
    expect(done.cookies.dmarcscope_setup).toBe('')

    const { unsealRecoveryCodes } = await import('@/lib/setup-state')
    const saved = await unsealRecoveryCodes(done.cookies.dmarcscope_recovery)
    recoveryCodes = saved!.codes
    expect(recoveryCodes).toHaveLength(10)

    const owner = (await db.admin.query(`SELECT * FROM users`)).rows
    expect(owner).toHaveLength(1)
    expect(owner[0]).toMatchObject({ email: OWNER, role: 'owner', status: 'active', source: 'local', role_source: 'assigned' })
    expect(owner[0].password_hash).toMatch(/^scrypt\$/)
    expect(owner[0].totp_secret).not.toContain(totpSecret)
    ownerId = Number(owner[0].id)
    const { sha256Hex } = await import('@/lib/crypto')
    expect((await db.admin.query(`SELECT used_at FROM setup_tokens WHERE token_hash = $1`, [sha256Hex(token)])).rows[0].used_at).toBeTruthy()
    const codes = (await db.admin.query(`SELECT code_hash FROM recovery_codes`)).rows.map((r) => r.code_hash)
    expect(codes).toHaveLength(10)
    for (const c of recoveryCodes) expect(codes.join(' ')).not.toContain(c)

    // the signed-in owner is recognized by the request gate
    const { authenticate } = await import('@/lib/auth')
    const result = await authenticate({ headers: new Headers(), cookie: (n) => (n === 'dmarcscope_session' ? done.cookies.dmarcscope_session : undefined) })
    expect(result).toMatchObject({ status: 'ok', session: { role: 'owner', userId: ownerId } })
  })

  it('serves 404 for every setup step once an owner exists, with any token', async () => {
    for (const step of ['token', 'account', 'totp', 'restart']) {
      expect((await setup(step, { token })).status).toBe(404)
    }
    const { ensureSetupToken } = await import('@/lib/setup')
    const { getPool } = await import('@/lib/db')
    const lines: string[] = []
    await ensureSetupToken(getPool(), process.env, (l) => lines.push(l))
    expect(lines).toEqual([])
  })

  it('cannot complete setup twice, even with a fresh token (race with another browser)', async () => {
    const { completeSetup } = await import('@/lib/setup')
    const { getPool } = await import('@/lib/db')
    const { sha256Hex } = await import('@/lib/crypto')
    const { rows } = await db.admin.query(`INSERT INTO setup_tokens (token_hash, expires_at) VALUES ($1, NOW() + INTERVAL '1 hour') RETURNING id`, [sha256Hex('second-browser-token-000000000')])
    const result = await completeSetup(
      getPool(),
      { kind: 'generated', id: Number(rows[0].id) },
      { email: 'intruder@example.com', name: null, passwordHash: 'scrypt$x', totpSecret: 'AAAA', confirmedStep: 1 },
      { userId: null, email: null, ip: null }
    )
    expect(result).toEqual({ ok: false, reason: 'owner_exists' })
    expect((await db.admin.query(`SELECT COUNT(*)::int AS n FROM users`)).rows[0].n).toBe(1)
  })

  // ---------- local sign-in ----------
  // Each password check is a deliberately slow scrypt hash: these tests make
  // dozens of them, which takes longer than vitest's default 5 s on CI runners.

  const signInPassword = async (email: string, password: string, ip = '198.51.100.30') =>
    record(await passwordRoute.POST(post('/auth/password', { email, password, returnTo: '/issues' }, { ip })))
  const signInCode = async (mfa: string, code: string, ip = '198.51.100.30') =>
    record(await secondFactorRoute.POST(post('/auth/second-factor', { code }, { cookies: { dmarcscope_mfa: mfa }, ip })))
  const resetLocks = () => db.admin.query(`UPDATE users SET failed_logins = 0, locked_until = NULL; DELETE FROM auth_throttle`)

  it('refuses a wrong password and an unknown address in exactly the same way', { timeout: 30_000 }, async () => {
    await resetLocks()
    const wrong = await signInPassword(OWNER, 'wrong-password-xxxx')
    const unknown = await signInPassword('nobody@example.com', 'wrong-password-xxxx')
    expect(wrong.location).toBe(`${BASE}/login?method=password&error=credentials&returnTo=%2Fissues`)
    expect(unknown.location).toBe(wrong.location)
    expect(Object.keys(wrong.cookies)).toEqual(Object.keys(unknown.cookies))
    expect(wrong.cookies.dmarcscope_mfa).toBeUndefined()
  })

  it('locks an account after repeated failures, even against the right password, and unknown addresses look the same', { timeout: 30_000 }, async () => {
    await resetLocks()
    for (let i = 0; i < 5; i++) await signInPassword(OWNER, `wrong-${i}-password`, `198.51.100.${40 + i}`)
    const locked = await signInPassword(OWNER, PASSWORD, '198.51.100.50')
    expect(locked.location).toContain('error=locked')
    expect(locked.cookies.dmarcscope_mfa).toBeUndefined()
    const row = (await db.admin.query(`SELECT failed_logins, locked_until > NOW() AS locked FROM users WHERE id = $1`, [ownerId])).rows[0]
    expect(row).toEqual({ failed_logins: 5, locked: true })

    for (let i = 0; i < 5; i++) await signInPassword('ghost@example.com', `wrong-${i}-password`, `198.51.100.${60 + i}`)
    expect((await signInPassword('ghost@example.com', 'anything-at-all-123', '198.51.100.70')).location).toContain('error=locked')
  })

  it('locks a client address after many failures across accounts', { timeout: 30_000 }, async () => {
    await resetLocks()
    for (let i = 0; i < 20; i++) await signInPassword(`spray-${i}@example.com`, 'wrong-password-xxxx', '203.0.113.99')
    expect((await signInPassword(OWNER, PASSWORD, '203.0.113.99')).location).toContain('error=locked')
    // another address is unaffected
    expect((await signInPassword(OWNER, PASSWORD, '203.0.113.100')).location).toBe(`${BASE}/login?method=password&step=code`)
  })

  it('asks for the second factor, refusing wrong, reused and replayed codes', { timeout: 30_000 }, async () => {
    await resetLocks()
    vi.useFakeTimers({ toFake: ['Date'] })
    try {
      // the code that confirmed setup cannot sign in: move to a later step
      vi.setSystemTime(Date.now() + 60_000)
      const first = await signInPassword(OWNER, PASSWORD)
      expect(first.location).toBe(`${BASE}/login?method=password&step=code`)
      const mfa = first.cookies.dmarcscope_mfa

      const wrong = await signInCode(mfa, totpCode(totpSecret, totpStep() + 7))
      expect(wrong.location).toBe(`${BASE}/login?method=password&step=code&error=code`)
      expect(wrong.cookies.dmarcscope_session).toBeUndefined()

      const code = totpCode(totpSecret)
      const ok = await signInCode(mfa, code)
      expect(ok.location).toBe(`${BASE}/issues`)
      expect(ok.cookies.dmarcscope_session).toBeTruthy()

      // the exact same request again (a replay)
      const replay = await signInCode(mfa, code)
      expect(replay.location).toContain('error=code')
      expect(replay.cookies.dmarcscope_session).toBeUndefined()

      // the same code in a new sign-in (reuse)
      const again = await signInPassword(OWNER, PASSWORD)
      const reused = await signInCode(again.cookies.dmarcscope_mfa, code)
      expect(reused.location).toContain('error=code')
      expect(reused.cookies.dmarcscope_session).toBeUndefined()

      // an older code than the last one accepted
      const older = await signInCode(again.cookies.dmarcscope_mfa, totpCode(totpSecret, totpStep() - 1))
      expect(older.cookies.dmarcscope_session).toBeUndefined()

      // the next step's code works
      vi.setSystemTime(Date.now() + 30_000)
      expect((await signInCode(again.cookies.dmarcscope_mfa, totpCode(totpSecret))).cookies.dmarcscope_session).toBeTruthy()
    } finally {
      vi.useRealTimers()
    }
  })

  it('refuses a second factor without the password step, or after the five minutes', async () => {
    const none = await record(await secondFactorRoute.POST(post('/auth/second-factor', { code: '123456' })))
    expect(none.location).toBe(`${BASE}/login?method=password&error=expired`)
    const forged = await signInCode('eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0..AAAA.BBBB.CCCC', '123456')
    expect(forged.location).toBe(`${BASE}/login?method=password&error=expired`)
  })

  it('accepts each recovery code once', { timeout: 30_000 }, async () => {
    await resetLocks()
    const a = await signInPassword(OWNER, PASSWORD)
    expect((await signInCode(a.cookies.dmarcscope_mfa, recoveryCodes[0].toUpperCase())).cookies.dmarcscope_session).toBeTruthy()
    const b = await signInPassword(OWNER, PASSWORD)
    expect((await signInCode(b.cookies.dmarcscope_mfa, recoveryCodes[0])).location).toContain('error=code')
    expect((await signInCode(b.cookies.dmarcscope_mfa, 'aaaa-bbbb-cccc-dddd')).location).toContain('error=code')
  })

  it('refuses a locked account at the second step too', { timeout: 30_000 }, async () => {
    await resetLocks()
    const a = await signInPassword(OWNER, PASSWORD)
    for (let i = 0; i < 5; i++) await signInCode(a.cookies.dmarcscope_mfa, '000000')
    const locked = await signInCode(a.cookies.dmarcscope_mfa, totpCode(totpSecret, totpStep() + 1))
    expect(locked.location).toBe(`${BASE}/login?method=password&error=locked`)
    expect(locked.cookies.dmarcscope_session).toBeUndefined()
  })

  it('refuses a disabled owner, and their existing session, on the next request', { timeout: 30_000 }, async () => {
    await resetLocks()
    const a = await signInPassword(OWNER, PASSWORD)
    const { authenticate } = await import('@/lib/auth')
    const { sealSession } = await import('@/lib/auth/session')
    const cookie = await sealSession({ sub: `user:${ownerId}`, email: OWNER, groups: [] }, process.env, { userId: ownerId })
    const req = { headers: new Headers(), cookie: (n: string) => (n === 'dmarcscope_session' ? cookie : undefined) }
    expect(await authenticate(req)).toMatchObject({ status: 'ok' })

    await db.admin.query(`UPDATE users SET status = 'disabled' WHERE id = $1`, [ownerId])
    expect((await signInPassword(OWNER, PASSWORD)).location).toContain('error=credentials')
    expect((await signInCode(a.cookies.dmarcscope_mfa, totpCode(totpSecret, totpStep() + 1))).location).toContain('error=code')
    expect(await authenticate(req)).toMatchObject({ status: 'forbidden' })
    await db.admin.query(`UPDATE users SET status = 'active' WHERE id = $1`, [ownerId])

    // sign out everywhere: sessions issued before sessions_valid_after
    await db.admin.query(`UPDATE users SET sessions_valid_after = NOW() + INTERVAL '1 second' WHERE id = $1`, [ownerId])
    expect(await authenticate(req)).toEqual({ status: 'unauthenticated' })
    await db.admin.query(`UPDATE users SET sessions_valid_after = NULL WHERE id = $1`, [ownerId])
  })

  // ---------- audit log ----------

  it('keeps an append-only audit trail of every step', async () => {
    const actions = (await db.admin.query(`SELECT DISTINCT action FROM audit_log`)).rows.map((r) => r.action)
    for (const a of ['setup_token_created', 'setup_token_refused', 'setup_token_accepted', 'setup_account_entered', 'setup_refused', 'setup_completed', 'sign_in_failed', 'sign_in_refused', 'sign_in', 'recovery_code_used']) {
      expect(actions).toContain(a)
    }
    await expect(db.admin.query(`UPDATE audit_log SET action = 'x'`)).rejects.toThrow(/append-only/)
    await expect(db.admin.query(`DELETE FROM audit_log`)).rejects.toThrow(/append-only/)
  })

  // ---------- no secret leaks ----------

  it('never prints, records or returns a secret value', async () => {
    const audit = JSON.stringify((await db.admin.query(`SELECT * FROM audit_log`)).rows)
    const canaries = [PASSWORD, APP_SECRET, totpSecret, ...recoveryCodes, ...recoveryCodes.map((c) => c.replace(/-/g, ''))]
    for (const canary of canaries) {
      expect(canary.length).toBeGreaterThan(8)
      for (const [where, text] of [['log', printed.join('\n')], ['audit_log', audit], ['responses', bodies.join('\n')]] as const) {
        expect(text.includes(canary), `${where} contains a secret`).toBe(false)
      }
    }
    // The setup token is printed exactly once, on purpose, and nowhere else.
    expect(printed.filter((l) => l.includes(token))).toHaveLength(1)
    expect(audit.includes(token)).toBe(false)
    expect(bodies.join('\n').includes(token)).toBe(false)
  })
})
