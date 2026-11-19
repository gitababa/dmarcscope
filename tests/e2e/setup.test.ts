// End-to-end first run against a running build of the app that has a fresh,
// migrated database and only the three required variables:
//   DATABASE_URL, APP_URL, APP_SECRET   (plus PORT / HOSTNAME to listen on)
// with its log written to a file. Skipped unless E2E_SETUP_BASE_URL is set.
//
//   E2E_SETUP_BASE_URL=http://127.0.0.1:3102 E2E_SETUP_LOG=/path/to/server.log \
//   E2E_SETUP_APP_SECRET=<the APP_SECRET it runs with> npx vitest run tests/e2e/setup.test.ts
//
// See .github/workflows/ci.yml for how CI starts it.

import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'
import { totpCode, totpStep } from '@/lib/crypto'

const BASE = process.env.E2E_SETUP_BASE_URL?.replace(/\/$/, '')
const LOG = process.env.E2E_SETUP_LOG
const APP_SECRET = process.env.E2E_SETUP_APP_SECRET || ''
const OWNER = 'owner@example.com'
const PASSWORD = 'e2e-canary-password-copper-otter-47'
const CRON_CANARY = 'e2e-canary-cron-token-9b2f71c04de3'

// A minimal browser: keeps cookies, follows redirects, posts forms.
class Browser {
  cookies = new Map<string, string>()

  private remember(res: Response) {
    for (const raw of res.headers.getSetCookie()) {
      const [pair] = raw.split(';')
      const name = pair.slice(0, pair.indexOf('='))
      const value = pair.slice(pair.indexOf('=') + 1)
      if (value === '' || /max-age=0/i.test(raw)) this.cookies.delete(name)
      else this.cookies.set(name, value)
    }
  }

  private headers(extra: Record<string, string> = {}) {
    const h: Record<string, string> = { ...extra }
    if (this.cookies.size) h.cookie = [...this.cookies].map(([k, v]) => `${k}=${v}`).join('; ')
    return h
  }

  async request(path: string, init: { method?: string; body?: BodyInit; headers?: Record<string, string> } = {}, maxHops = 10) {
    let url = new URL(path, BASE)
    let method = init.method ?? 'GET'
    let body = init.body
    const hops: string[] = []
    for (let i = 0; i <= maxHops; i++) {
      const res = await fetch(url, { method, body, redirect: 'manual', headers: this.headers(method === 'GET' ? {} : { origin: BASE!, ...init.headers }) })
      this.remember(res)
      const location = res.headers.get('location')
      if (res.status >= 300 && res.status < 400 && location) {
        url = new URL(location, url)
        hops.push(url.pathname + url.search)
        method = 'GET'
        body = undefined
        continue
      }
      return { res, status: res.status, url, hops, text: await res.text() }
    }
    throw new Error(`too many redirects: ${hops.join(' -> ')}`)
  }

  get(path: string, maxHops = 10) {
    return this.request(path, {}, maxHops)
  }

  post(path: string, fields: Record<string, string>, maxHops = 10) {
    return this.request(path, { method: 'POST', body: new URLSearchParams(fields).toString(), headers: { 'content-type': 'application/x-www-form-urlencoded' } }, maxHops)
  }
}

const unescape = (s: string) => s.replace(/&amp;/g, '&').replace(/&quot;/g, '"').replace(/&#x27;/g, "'").replace(/&lt;/g, '<').replace(/&gt;/g, '>')

// The server-action form for one setting on /admin, as a browser without
// JavaScript would submit it.
function settingForm(html: string, key: string): Record<string, string> {
  const forms = html.match(/<form[\s\S]*?<\/form>/g) ?? []
  const form = forms.find((f) => f.includes(`name="key" value="${key}"`))
  if (!form) throw new Error(`no form for ${key}`)
  const fields: Record<string, string> = {}
  for (const input of form.match(/<input[^>]*>/g) ?? []) {
    const name = /name="([^"]*)"/.exec(input)?.[1]
    if (!name) continue
    fields[unescape(name)] = unescape(/value="([^"]*)"/.exec(input)?.[1] ?? '')
  }
  return fields
}

describe.skipIf(!BASE || !LOG)('first run, end to end', () => {
  const owner = new Browser()
  let token = ''
  let secret = ''
  let recovery: string[] = []
  const pages: string[] = []

  it('serves only the setup wizard until there is an owner', async () => {
    const b = new Browser()
    for (const path of ['/', '/issues', '/admin', '/login']) {
      const r = await b.get(path)
      expect(r.url.pathname, path).toBe('/setup')
      expect(r.status).toBe(200)
      expect(r.text).toContain('Setup token')
      expect(r.text).not.toContain('Problem sources')
    }
    const api = await fetch(`${BASE}/api/anything`)
    expect(api.status).toBe(503)
    expect(await api.json()).toEqual({ ok: false, error: 'setup_required' })
    expect((await fetch(`${BASE}/api/healthz`)).status).toBe(200)
  })

  it('wrote a one-time setup token to the log, once', async () => {
    const lines = readFileSync(LOG!, 'utf8').split('\n').filter((l) => l.includes('one-time setup token'))
    expect(lines).toHaveLength(1)
    token = /: (\S+)$/.exec(lines[0])![1]
  })

  it('refuses a wrong token and a cross-origin post', async () => {
    const wrong = await owner.post('/setup/token', { token: 'wrong' })
    expect(wrong.url.pathname + wrong.url.search).toBe('/setup?error=token_invalid')
    expect(wrong.text).toContain('not valid')
    const cross = await fetch(`${BASE}/setup/token`, {
      method: 'POST',
      redirect: 'manual',
      headers: { origin: 'https://evil.example', 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ token }).toString(),
    })
    expect(cross.status).toBe(403)
  })

  it('creates the owner: token, account, authenticator, recovery codes', async () => {
    const step1 = await owner.post('/setup/token', { token })
    expect(step1.url.pathname).toBe('/setup')
    expect(step1.text).toContain('Password again')

    const weak = await owner.post('/setup/account', { email: OWNER, name: 'Owner', password: 'password1234', password_confirm: 'password1234' })
    expect(weak.url.search).toBe('?error=password_common')

    const step2 = await owner.post('/setup/account', { email: OWNER, name: 'Owner', password: PASSWORD, password_confirm: PASSWORD })
    expect(step2.text).toContain('Code from the app')
    expect(step2.text).toContain('aria-label="QR code for the authenticator app"')
    secret = /data-testid="totp-secret">([A-Z2-7 ]+)</.exec(step2.text)![1].replace(/ /g, '')
    expect(secret).toMatch(/^[A-Z2-7]{32}$/)

    const done = await owner.post('/setup/totp', { code: totpCode(secret) })
    expect(done.url.pathname).toBe('/welcome')
    expect(done.text).toContain('Save your recovery codes')
    expect(done.text).toContain(OWNER)
    recovery = [...done.text.matchAll(/<li>([a-z2-7]{4}-[a-z2-7]{4}-[a-z2-7]{4}-[a-z2-7]{4})<\/li>/g)].map((m) => m[1])
    expect(recovery).toHaveLength(10)
  })

  it('is a signed-in owner with the administration pages', async () => {
    for (const path of ['/admin', '/admin/users', '/admin/audit', '/', '/issues']) {
      const r = await owner.get(path)
      expect(r.status, path).toBe(200)
      expect(r.url.pathname).toBe(path)
      pages.push(r.text)
    }
    expect(pages[0]).toContain('Machine endpoint token')
    expect(pages[1]).toContain(OWNER)
    expect(pages[2]).toContain('setup_completed')
  })

  it('answers 404 on /setup from now on', async () => {
    expect((await fetch(`${BASE}/setup`)).status).toBe(404)
    expect((await owner.get('/setup')).status).toBe(404)
    const again = await fetch(`${BASE}/setup/token`, {
      method: 'POST',
      redirect: 'manual',
      headers: { origin: BASE!, 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ token }).toString(),
    })
    expect(again.status).toBe(404)
  })

  it('stores a secret setting without ever showing it again', { timeout: 20_000 }, async () => {
    const admin = await owner.get('/admin')
    const fields = settingForm(admin.text, 'cron.secret')
    fields.value = CRON_CANARY
    const form = new FormData()
    for (const [k, v] of Object.entries(fields)) form.set(k, v)
    const saved = await owner.request('/admin', { method: 'POST', body: form })
    expect(saved.url.search).toBe('?saved=cron.secret')
    expect(saved.text).not.toContain(CRON_CANARY)
    // and the machine endpoints accept it within the settings cache window
    // (SETTINGS_CACHE_SECONDS, 5 by default): 503 = authorized, no ingest yet
    let status = 0
    for (let i = 0; i < 16 && status !== 503; i++) {
      if (i) await new Promise((r) => setTimeout(r, 500))
      status = (await fetch(`${BASE}/api/cron/status`, { headers: { authorization: `Bearer ${CRON_CANARY}` } })).status
    }
    expect(status).toBe(503)
    expect((await fetch(`${BASE}/api/cron/status`, { headers: { authorization: 'Bearer wrong-token-wrong-token' } })).status).toBe(401)
    for (const path of ['/admin', '/admin/audit']) pages.push((await owner.get(path)).text)
  })

  it('signs the owner in again with password and TOTP, refusing a replayed code', async () => {
    const b = new Browser()
    const wrong = await b.post('/auth/password', { email: OWNER, password: 'not-the-password-123' })
    expect(wrong.url.search).toContain('error=credentials')

    const pw = await b.post('/auth/password', { email: OWNER, password: PASSWORD, returnTo: '/issues' })
    expect(pw.url.search).toBe('?method=password&step=code')
    expect(pw.text).toContain('authenticator app')
    const mfa = b.cookies.get('dmarcscope_mfa')!

    // setup used the current step; the next one is within the allowed drift
    const code = totpCode(secret, totpStep() + 1)
    const ok = await b.post('/auth/second-factor', { code })
    expect(ok.url.pathname).toBe('/issues')
    expect(ok.text).toContain(OWNER)

    const replay = new Browser()
    replay.cookies.set('dmarcscope_mfa', mfa)
    const again = await replay.post('/auth/second-factor', { code })
    expect(again.url.search).toContain('error=code')
    expect(replay.cookies.has('dmarcscope_session')).toBe(false)
  })

  it('never shows a secret in a page or writes one to the log', async () => {
    const log = readFileSync(LOG!, 'utf8')
    const canaries = [PASSWORD, secret, CRON_CANARY, ...recovery, ...(APP_SECRET ? [APP_SECRET] : [])]
    for (const canary of canaries) {
      expect(log.includes(canary), 'server log').toBe(false)
      pages.forEach((p, i) => expect(p.includes(canary), `page ${i}`).toBe(false))
    }
    // the setup token: once in the log on purpose, never on a page
    expect(log.split(token).length - 1).toBe(1)
    for (const p of pages) expect(p.includes(token)).toBe(false)
  })
})
