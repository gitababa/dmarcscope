import { createServer, type Server } from 'node:http'
import type { AddressInfo } from 'node:net'
import { SignJWT, exportJWK, generateKeyPair } from 'jose'
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest'
import { authProvider, authenticate as authenticateWith } from '@/lib/auth'
import { MemoryDirectory } from '../helpers/memory-directory'
import { sealSession, sessionCookieName } from '@/lib/auth/session'

// Who is in the database: nobody, so the access lists alone decide, as in
// 1.1.0. (How the database changes that is tested in access-resolution.test.ts.)
let dir = new MemoryDirectory()
beforeEach(() => {
  dir = new MemoryDirectory()
})
const authenticate = (r: Parameters<typeof authenticateWith>[0], env: Record<string, string | undefined>) => authenticateWith(r, env, dir)

const req = (headers: Record<string, string> = {}, cookies: Record<string, string> = {}) => ({
  headers: { get: (name: string) => headers[name.toLowerCase()] ?? null },
  cookie: (name: string) => cookies[name],
})

describe('authProvider', () => {
  it('manages sign-in in the app when unset, and refuses unknown values', () => {
    expect(authProvider({})).toBe('local')
    expect(() => authProvider({ AUTH_PROVIDER: 'ldap' })).toThrow(/Unknown AUTH_PROVIDER/)
    expect(authProvider({ AUTH_PROVIDER: 'OIDC' })).toBe('oidc')
  })

  it('refuses "none" in production unless explicitly acknowledged', () => {
    expect(authProvider({ AUTH_PROVIDER: 'none' })).toBe('none')
    expect(() => authProvider({ AUTH_PROVIDER: 'none', NODE_ENV: 'production' })).toThrow(/refused in production/)
    expect(authProvider({ AUTH_PROVIDER: 'none', NODE_ENV: 'production', AUTH_ALLOW_INSECURE_NONE: 'true' })).toBe('none')
    // same spellings as every other boolean setting
    expect(authProvider({ AUTH_PROVIDER: 'none', NODE_ENV: 'production', AUTH_ALLOW_INSECURE_NONE: 'TRUE' })).toBe('none')
    expect(() => authProvider({ AUTH_PROVIDER: 'none', NODE_ENV: 'production', AUTH_ALLOW_INSECURE_NONE: 'false' })).toThrow(/refused/)
  })
})

describe('oidc sessions', () => {
  const env = {
    AUTH_PROVIDER: 'oidc',
    SESSION_SECRET: 'k'.repeat(40),
    APP_URL: 'http://localhost:3000',
    ALLOWED_EMAILS: 'viewer@example.com',
    ADMIN_EMAILS: 'admin@example.com',
  }

  it('is unauthenticated without a cookie', async () => {
    expect(await authenticate(req(), env)).toEqual({ status: 'unauthenticated' })
  })

  it('maps a valid session to a role, re-evaluated per request', async () => {
    const cookie = await sealSession({ sub: '1', email: 'viewer@example.com', groups: [] }, env)
    const r = req({}, { [sessionCookieName(env)]: cookie })
    expect(await authenticate(r, env)).toMatchObject({ status: 'ok', session: { role: 'viewer' } })
    // removed from the allowlist → same cookie no longer grants access
    expect(await authenticate(r, { ...env, ALLOWED_EMAILS: '' })).toMatchObject({ status: 'forbidden' })
    expect(await authenticate(r, { ...env, ADMIN_EMAILS: 'viewer@example.com' })).toMatchObject({
      status: 'ok',
      session: { role: 'admin' },
    })
  })
})

describe('proxy-header', () => {
  const base = { AUTH_PROVIDER: 'proxy-header', ALLOWED_EMAIL_DOMAINS: 'example.com' }

  it('reads the forwarded email and groups', async () => {
    const env = { ...base, ADMIN_GROUPS: 'dmarc-admins' }
    const r = req({ 'x-forwarded-email': 'Ops@Example.com', 'x-forwarded-groups': 'staff, dmarc-admins' })
    expect(await authenticate(r, env)).toMatchObject({
      status: 'ok',
      session: { role: 'admin', identity: { email: 'ops@example.com', groups: ['dmarc-admins'] } },
    })
  })

  it('is unauthenticated without the header or with a malformed one', async () => {
    expect(await authenticate(req(), base)).toEqual({ status: 'unauthenticated' })
    expect(await authenticate(req({ 'x-forwarded-email': 'a@example.com, b@example.com' }), base)).toEqual({
      status: 'unauthenticated',
    })
  })

  it('refuses to run in production without a shared secret or an explicit acknowledgement', async () => {
    const prod = { ...base, NODE_ENV: 'production' }
    await expect(authenticate(req({ 'x-forwarded-email': 'a@example.com' }), prod)).rejects.toThrow(/AUTH_PROXY_SHARED_SECRET/)
    expect(
      await authenticate(req({ 'x-forwarded-email': 'a@example.com' }), { ...prod, AUTH_PROXY_TRUST_NETWORK: 'true' })
    ).toMatchObject({ status: 'ok' })
  })

  it('requires the shared secret header when one is configured', async () => {
    const env = { ...base, NODE_ENV: 'production', AUTH_PROXY_SHARED_SECRET: 'p'.repeat(24) }
    const email = { 'x-forwarded-email': 'a@example.com' }
    expect(await authenticate(req(email), env)).toEqual({ status: 'unauthenticated' })
    expect(await authenticate(req({ ...email, 'x-proxy-secret': 'wrong' }), env)).toEqual({ status: 'unauthenticated' })
    expect(await authenticate(req({ ...email, 'x-proxy-secret': 'p'.repeat(24) }), env)).toMatchObject({ status: 'ok' })
  })
})

describe('proxy-jwt', () => {
  let server: Server
  let jwksUrl: string
  let sign: (claims: Record<string, unknown>, opts?: { iss?: string; aud?: string; exp?: string }) => Promise<string>
  let signWithOtherKey: typeof sign

  beforeAll(async () => {
    const good = await generateKeyPair('ES256')
    const other = await generateKeyPair('ES256')
    const jwk = { ...(await exportJWK(good.publicKey)), kid: 'k1', alg: 'ES256', use: 'sig' }
    server = createServer((_req, res) => {
      res.setHeader('content-type', 'application/json')
      res.end(JSON.stringify({ keys: [jwk] }))
    })
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
    jwksUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}/jwks`

    const maker = (key: CryptoKey) => (claims: Record<string, unknown>, opts: { iss?: string; aud?: string; exp?: string } = {}) =>
    {
      const jwt = new SignJWT(claims)
        .setProtectedHeader({ alg: 'ES256', kid: 'k1' })
        .setIssuer(opts.iss ?? 'https://proxy.example')
        .setAudience(opts.aud ?? 'dmarcscope-app')
        .setIssuedAt()
      if (opts.exp !== 'never') jwt.setExpirationTime(opts.exp ?? '5m')
      return jwt.sign(key)
    }
    sign = maker(good.privateKey as CryptoKey)
    signWithOtherKey = maker(other.privateKey as CryptoKey)
  })

  afterAll(() => new Promise<void>((resolve) => server.close(() => resolve())))

  const env = () => ({
    AUTH_PROVIDER: 'proxy-jwt',
    AUTH_PROXY_JWT_HEADER: 'X-Assertion',
    AUTH_PROXY_JWKS_URL: jwksUrl,
    AUTH_PROXY_ALLOW_INSECURE_JWKS: 'true',
    AUTH_PROXY_ISSUER: 'https://proxy.example',
    AUTH_PROXY_AUDIENCE: 'dmarcscope-app',
    ALLOWED_EMAILS: 'a@example.com',
  })

  it('accepts a correctly signed assertion', async () => {
    const token = await sign({ sub: 'u1', email: 'A@example.com' })
    expect(await authenticate(req({ 'x-assertion': token }), env())).toMatchObject({
      status: 'ok',
      session: { role: 'viewer', identity: { email: 'a@example.com', sub: 'u1' } },
    })
  })

  it('rejects wrong audience, issuer, key, expiry and unsigned tokens', async () => {
    const cases = [
      await sign({ email: 'a@example.com' }, { aud: 'some-other-app' }),
      await sign({ email: 'a@example.com' }, { iss: 'https://evil.example' }),
      await signWithOtherKey({ email: 'a@example.com' }),
      await sign({ email: 'a@example.com' }, { exp: '-10m' }),
      // no expiry at all, and things that only resemble one address
      await sign({ email: 'a@example.com' }, { exp: 'never' }),
      await sign({ email: 'a@example.com, admin@example.com' }),
      await sign({ email: 'a@example.com@evil.test' }),
      await sign({ email: ' a@example.com' }),
      // alg=none
      `${Buffer.from('{"alg":"none"}').toString('base64url')}.${Buffer.from(
        JSON.stringify({ email: 'a@example.com', iss: 'https://proxy.example', aud: 'dmarcscope-app' })
      ).toString('base64url')}.`,
      'garbage',
    ]
    for (const token of cases) {
      expect(await authenticate(req({ 'x-assertion': token }), env())).toEqual({ status: 'unauthenticated' })
    }
    expect(await authenticate(req(), env())).toEqual({ status: 'unauthenticated' })
  })

  it('authenticated but not on a list is forbidden, not unauthenticated', async () => {
    const token = await sign({ email: 'stranger@example.com' })
    expect(await authenticate(req({ 'x-assertion': token }), env())).toMatchObject({ status: 'forbidden' })
  })

  it('insists on an audience and https keys', async () => {
    const token = await sign({ email: 'a@example.com' })
    await expect(authenticate(req({ 'x-assertion': token }), { ...env(), AUTH_PROXY_AUDIENCE: '' })).rejects.toThrow(/AUDIENCE/)
    await expect(
      authenticate(req({ 'x-assertion': token }), { ...env(), AUTH_PROXY_ALLOW_INSECURE_JWKS: '' })
    ).rejects.toThrow(/https/)
  })

  it('knows the GCP IAP and Cloudflare Access presets', async () => {
    const { jwtProxyConfig } = await import('@/lib/auth/proxy-providers')
    expect(jwtProxyConfig({ AUTH_PROXY_PRESET: 'gcp-iap', AUTH_PROXY_AUDIENCE: '/projects/1/global/backendServices/2' })).toMatchObject({
      header: 'x-goog-iap-jwt-assertion',
      issuer: 'https://cloud.google.com/iap',
      jwksUrl: 'https://www.gstatic.com/iap/verify/public_key-jwk',
    })
    expect(
      jwtProxyConfig({
        AUTH_PROXY_PRESET: 'cloudflare-access',
        AUTH_PROXY_ISSUER: 'https://team.cloudflareaccess.com',
        AUTH_PROXY_AUDIENCE: 'aud-tag',
      })
    ).toMatchObject({
      header: 'cf-access-jwt-assertion',
      jwksUrl: 'https://team.cloudflareaccess.com/cdn-cgi/access/certs',
    })
    expect(() => jwtProxyConfig({ AUTH_PROXY_PRESET: 'cloudflare-access', AUTH_PROXY_AUDIENCE: 'x' })).toThrow(/ISSUER/)
  })
})
