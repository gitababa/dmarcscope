// End-to-end sign-in against a running build of the app and an in-process
// mock OpenID Connect provider. Skipped unless E2E_BASE_URL is set.
//
// Start the app with (see .github/workflows/ci.yml):
//   AUTH_PROVIDER=oidc OIDC_ISSUER=http://127.0.0.1:9911 OIDC_ALLOW_INSECURE_ISSUER=true
//   OIDC_CLIENT_ID=dmarcscope OIDC_CLIENT_SECRET=e2e-client-secret
//   SESSION_SECRET=<32+ chars> APP_URL=<E2E_BASE_URL> CRON_SECRET=<16+ chars>
//   ADMIN_EMAILS=admin@example.com ALLOWED_GROUPS=dmarc-viewers
// then: E2E_BASE_URL=http://127.0.0.1:3101 npx vitest run tests/e2e

import { createHash, randomUUID } from 'node:crypto'
import { createServer, type Server } from 'node:http'
import { SignJWT, exportJWK, generateKeyPair } from 'jose'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

const BASE = process.env.E2E_BASE_URL?.replace(/\/$/, '')
const IDP_PORT = Number(process.env.E2E_IDP_PORT || 9911)
const ISSUER = `http://127.0.0.1:${IDP_PORT}`
const CLIENT_ID = 'dmarcscope'
const CLIENT_SECRET = 'e2e-client-secret'

type User = { sub: string; email?: string; email_verified?: boolean; groups?: string[]; name?: string }

// ---------- mock identity provider ----------

let idp: Server
let nextUser: User = { sub: 'nobody' }
const codes = new Map<string, { user: User; nonce: string; challenge: string; redirectUri: string }>()

async function startIdp() {
  const { publicKey, privateKey } = await generateKeyPair('RS256')
  const jwk = { ...(await exportJWK(publicKey)), kid: 'e2e', alg: 'RS256', use: 'sig' }

  idp = createServer(async (req, res) => {
    const url = new URL(req.url!, ISSUER)
    const json = (status: number, body: unknown) => {
      res.writeHead(status, { 'content-type': 'application/json' })
      res.end(JSON.stringify(body))
    }
    if (url.pathname === '/.well-known/openid-configuration') {
      return json(200, {
        issuer: ISSUER,
        authorization_endpoint: `${ISSUER}/authorize`,
        token_endpoint: `${ISSUER}/token`,
        userinfo_endpoint: `${ISSUER}/userinfo`,
        jwks_uri: `${ISSUER}/jwks`,
        response_types_supported: ['code'],
        subject_types_supported: ['public'],
        id_token_signing_alg_values_supported: ['RS256'],
        code_challenge_methods_supported: ['S256'],
        token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post'],
      })
    }
    if (url.pathname === '/jwks') return json(200, { keys: [jwk] })
    if (url.pathname === '/authorize') {
      const q = url.searchParams
      if (q.get('client_id') !== CLIENT_ID || q.get('response_type') !== 'code' || q.get('code_challenge_method') !== 'S256') {
        return json(400, { error: 'invalid_request' })
      }
      const code = randomUUID()
      codes.set(code, {
        user: nextUser,
        nonce: q.get('nonce')!,
        challenge: q.get('code_challenge')!,
        redirectUri: q.get('redirect_uri')!,
      })
      const back = new URL(q.get('redirect_uri')!)
      back.searchParams.set('code', code)
      back.searchParams.set('state', q.get('state')!)
      res.writeHead(302, { location: back.href })
      return res.end()
    }
    if (url.pathname === '/token' && req.method === 'POST') {
      let body = ''
      for await (const chunk of req) body += chunk
      const form = new URLSearchParams(body)
      const basic = req.headers.authorization?.startsWith('Basic ')
        ? Buffer.from(req.headers.authorization.slice(6), 'base64').toString()
        : `${form.get('client_id')}:${form.get('client_secret')}`
      const grant = codes.get(form.get('code') || '')
      codes.delete(form.get('code') || '')
      const challenge = createHash('sha256').update(form.get('code_verifier') || '').digest('base64url')
      if (
        decodeURIComponent(basic) !== `${CLIENT_ID}:${CLIENT_SECRET}` ||
        !grant ||
        grant.challenge !== challenge ||
        grant.redirectUri !== form.get('redirect_uri')
      ) {
        return json(400, { error: 'invalid_grant' })
      }
      const idToken = await new SignJWT({ ...grant.user, nonce: grant.nonce })
        .setProtectedHeader({ alg: 'RS256', kid: 'e2e' })
        .setIssuer(ISSUER)
        .setAudience(CLIENT_ID)
        .setIssuedAt()
        .setExpirationTime('5m')
        .sign(privateKey)
      return json(200, { access_token: `at-${grant.user.sub}`, token_type: 'Bearer', expires_in: 300, id_token: idToken })
    }
    if (url.pathname === '/userinfo') {
      return json(200, { sub: (req.headers.authorization || '').replace('Bearer at-', '') })
    }
    json(404, { error: 'not_found' })
  })
  await new Promise<void>((resolve) => idp.listen(IDP_PORT, '127.0.0.1', resolve))
}

// ---------- a minimal browser: follows redirects, keeps cookies ----------

class Browser {
  cookies = new Map<string, string>()
  setCookieHeaders: string[] = []

  async get(target: string, opts: { maxHops?: number } = {}) {
    let url = new URL(target, BASE)
    const hops: string[] = []
    for (let i = 0; i <= (opts.maxHops ?? 10); i++) {
      const isApp = url.origin === new URL(BASE!).origin
      const res = await fetch(url, {
        redirect: 'manual',
        headers: isApp && this.cookies.size ? { cookie: [...this.cookies].map(([k, v]) => `${k}=${v}`).join('; ') } : {},
      })
      if (isApp) {
        for (const raw of res.headers.getSetCookie()) {
          this.setCookieHeaders.push(raw)
          const [pair] = raw.split(';')
          const eq = pair.indexOf('=')
          const name = pair.slice(0, eq)
          const value = pair.slice(eq + 1)
          if (value === '' || /max-age=0/i.test(raw)) this.cookies.delete(name)
          else this.cookies.set(name, value)
        }
      }
      const location = res.headers.get('location')
      if (res.status >= 300 && res.status < 400 && location) {
        url = new URL(location, url)
        hops.push(url.origin === new URL(BASE!).origin ? url.pathname + url.search : url.origin + url.pathname)
        continue
      }
      return { res, url, hops, text: await res.text() }
    }
    throw new Error(`too many redirects: ${hops.join(' -> ')}`)
  }

  // "Clicks" the sign-in button: the login page links to /auth/login.
  async signIn(user: User, returnTo = '/') {
    nextUser = user
    return this.get(returnTo === '/' ? '/auth/login' : `/auth/login?returnTo=${encodeURIComponent(returnTo)}`)
  }
}

// ---------- tests ----------

describe.skipIf(!BASE)('OIDC sign-in, end to end', () => {
  beforeAll(startIdp)
  afterAll(() => new Promise<void>((resolve) => idp.close(() => resolve())))

  it('sends anonymous visitors to the login page and serves nothing else', async () => {
    const b = new Browser()
    const { url, text, res } = await b.get('/issues?range=30d', { maxHops: 1 })
    expect(url.pathname).toBe('/login')
    expect(url.searchParams.get('returnTo')).toBe('/issues?range=30d')
    expect(res.status).toBe(200)
    expect(text).toContain('Sign in')
    expect(text).not.toContain('Problem sources')

    const api = await fetch(`${BASE}/api/does-not-exist`, { redirect: 'manual' })
    expect(api.status).toBe(401)
  })

  it('signs an admin in and returns them to the page they asked for', async () => {
    const b = new Browser()
    const { url, hops, text, res } = await b.signIn({ sub: 'u-admin', email: 'Admin@Example.com', email_verified: true }, '/issues?range=30d')
    expect(hops.some((h) => h.startsWith(`${ISSUER}/authorize`))).toBe(true)
    expect(url.pathname + url.search).toBe('/issues?range=30d')
    expect(res.status).toBe(200)
    expect(text).toContain('admin@example.com')
    expect(text).toContain('Sign out')

    const session = b.setCookieHeaders.find((c) => c.includes('dmarcscope_session='))!
    expect(session).toMatch(/HttpOnly/i)
    expect(session).toMatch(/SameSite=lax/i)
    expect(session).toMatch(/Path=\//i)
    // the login-state cookie is gone once it has been used
    expect([...b.cookies.keys()].filter((k) => k.includes('login'))).toEqual([])
  })

  it('grants viewers access through a group claim, without admin controls', async () => {
    const b = new Browser()
    const { url, text } = await b.signIn({ sub: 'u-viewer', email: 'viewer@example.com', groups: ['staff', 'dmarc-viewers'] })
    expect(url.pathname).toBe('/')
    expect(text).toContain('viewer@example.com')
    expect(text).not.toContain('>admin<')
  })

  it('authenticates but denies people who are on no access list', async () => {
    const b = new Browser()
    const { url, text } = await b.signIn({ sub: 'u-stranger', email: 'stranger@elsewhere.test', email_verified: true })
    expect(url.pathname).toBe('/denied')
    expect(text).toContain('stranger@elsewhere.test')
    expect(text).toContain('Access not granted')
    // and the dashboard stays closed with that session
    const again = await b.get('/', { maxHops: 3 })
    expect(again.url.pathname).toBe('/denied')
  })

  it('rejects unverified email addresses and identities without an email', async () => {
    const unverified = await new Browser().signIn({ sub: 'u1', email: 'admin@example.com', email_verified: false })
    expect(unverified.url.pathname + unverified.url.search).toBe('/login?error=unverified_email')
    const noEmail = await new Browser().signIn({ sub: 'u2' })
    expect(noEmail.url.pathname + noEmail.url.search).toBe('/login?error=no_email')
  })

  it('rejects a callback without the login cookie, with a wrong state, or a replayed code', async () => {
    const noCookie = await new Browser().get('/auth/callback?code=abc&state=xyz')
    expect(noCookie.url.pathname + noCookie.url.search).toBe('/login?error=expired')

    // Start a real login, then tamper with the state on the way back.
    nextUser = { sub: 'u-admin', email: 'admin@example.com' }
    const b = new Browser()
    const start = await fetch(`${BASE}/auth/login`, { redirect: 'manual' })
    for (const raw of start.headers.getSetCookie()) {
      const [pair] = raw.split(';')
      b.cookies.set(pair.slice(0, pair.indexOf('=')), pair.slice(pair.indexOf('=') + 1))
    }
    const authorize = await fetch(start.headers.get('location')!, { redirect: 'manual' })
    const callback = new URL(authorize.headers.get('location')!)
    const good = callback.pathname + callback.search
    callback.searchParams.set('state', 'tampered')
    const tampered = await b.get(callback.pathname + callback.search)
    expect(tampered.url.pathname + tampered.url.search).toBe('/login?error=failed')
    expect([...b.cookies.keys()].some((k) => k.includes('session'))).toBe(false)

    // The original (untampered) callback URL is now useless too: the login
    // cookie was cleared when the tampered attempt failed.
    const replay = await b.get(good)
    expect(replay.url.pathname + replay.url.search).toBe('/login?error=expired')
  })

  it('ignores forged and garbage session cookies', async () => {
    const b = new Browser()
    b.cookies.set('dmarcscope_session', 'eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0..AAAA.BBBB.CCCC')
    const { url } = await b.get('/', { maxHops: 1 })
    expect(url.pathname).toBe('/login')
  })

  it('does not follow an off-site returnTo', async () => {
    const b = new Browser()
    const { url } = await b.signIn({ sub: 'u-admin', email: 'admin@example.com' }, 'https://evil.example/')
    expect(url.origin).toBe(new URL(BASE!).origin)
    expect(url.pathname).toBe('/')
  })

  it('sends security headers and a nonce-based CSP', async () => {
    const res = await fetch(`${BASE}/login`)
    const csp = res.headers.get('content-security-policy')!
    expect(csp).toMatch(/script-src 'self' 'nonce-[A-Za-z0-9+/=]+' 'strict-dynamic'/)
    expect(csp).not.toMatch(/script-src[^;]*unsafe-inline/)
    expect(csp).toContain("frame-ancestors 'none'")
    expect(res.headers.get('x-frame-options')).toBe('DENY')
    expect(res.headers.get('x-content-type-options')).toBe('nosniff')
    expect(res.headers.get('strict-transport-security')).toContain('max-age=')
    expect(res.headers.get('x-powered-by')).toBeNull()
    const html = await res.text()
    const nonce = /'nonce-([^']+)'/.exec(csp)![1]
    expect(html).toContain(`nonce="${nonce}"`)
  })

  it('keeps probes open and machine endpoints behind the bearer token', async () => {
    expect((await fetch(`${BASE}/api/healthz`)).status).toBe(200)
    expect((await fetch(`${BASE}/api/readyz`)).status).toBe(200)
    expect((await fetch(`${BASE}/api/cron/dns-check`)).status).toBe(401)
    expect((await fetch(`${BASE}/api/cron/dns-check`, { headers: { authorization: 'Bearer wrong' } })).status).toBe(401)
    if (process.env.E2E_CRON_SECRET) {
      const ok = await fetch(`${BASE}/api/cron/dns-check?domain=not-tracked.example`, {
        headers: { authorization: `Bearer ${process.env.E2E_CRON_SECRET}` },
      })
      expect(ok.status).toBe(404)
    }
  })
})
