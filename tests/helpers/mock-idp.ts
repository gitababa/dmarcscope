// An in-process OpenID provider for tests. It checks what a real one checks
// (client credentials, registered redirect URI, PKCE) and can be told who
// signs in next.

import { createHash, randomUUID } from 'node:crypto'
import { createServer, type Server } from 'node:http'
import type { AddressInfo } from 'node:net'
import { SignJWT, exportJWK, generateKeyPair } from 'jose'

export type MockUser = { sub: string; email?: string; email_verified?: boolean; groups?: string[]; name?: string; [k: string]: unknown }

export class MockIdp {
  server!: Server
  issuer = ''
  clientId = 'dmarcscope-test'
  clientSecret = 'mock-idp-client-secret'
  redirectUris: string[] = []
  nextUser: MockUser = { sub: 'nobody' }
  // Extra claims served from a UserInfo endpoint (none: no endpoint).
  userinfo: Record<string, unknown> | null = null
  private codes = new Map<string, { user: MockUser; nonce: string; challenge: string; redirectUri: string }>()

  async start(): Promise<this> {
    const { publicKey, privateKey } = await generateKeyPair('RS256')
    const jwk = { ...(await exportJWK(publicKey)), kid: 'k', alg: 'RS256', use: 'sig' }
    this.server = createServer(async (req, res) => {
      const url = new URL(req.url!, this.issuer)
      const json = (status: number, body: unknown) => {
        res.writeHead(status, { 'content-type': 'application/json' })
        res.end(JSON.stringify(body))
      }
      if (url.pathname === '/.well-known/openid-configuration') {
        return json(200, {
          issuer: this.issuer,
          authorization_endpoint: `${this.issuer}/authorize`,
          token_endpoint: `${this.issuer}/token`,
          jwks_uri: `${this.issuer}/jwks`,
          ...(this.userinfo ? { userinfo_endpoint: `${this.issuer}/userinfo` } : {}),
          response_types_supported: ['code'],
          subject_types_supported: ['public'],
          id_token_signing_alg_values_supported: ['RS256'],
          code_challenge_methods_supported: ['S256'],
          token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post'],
        })
      }
      if (url.pathname === '/jwks') return json(200, { keys: [jwk] })
      if (url.pathname === '/userinfo' && this.userinfo) return json(200, { sub: this.nextUser.sub, ...this.userinfo })
      if (url.pathname === '/authorize') {
        const q = url.searchParams
        const redirectUri = q.get('redirect_uri') || ''
        // A real provider refuses an unregistered redirect URI (some show an
        // error page, some send the error back): we send it back.
        if (q.get('client_id') !== this.clientId || !this.redirectUris.includes(redirectUri)) {
          const back = new URL(redirectUri || 'http://invalid.test/')
          back.searchParams.set('error', q.get('client_id') !== this.clientId ? 'unauthorized_client' : 'redirect_uri_mismatch')
          back.searchParams.set('state', q.get('state') || '')
          res.writeHead(302, { location: back.href })
          return res.end()
        }
        const code = randomUUID()
        this.codes.set(code, { user: this.nextUser, nonce: q.get('nonce')!, challenge: q.get('code_challenge')!, redirectUri })
        const back = new URL(redirectUri)
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
        const grant = this.codes.get(form.get('code') || '')
        this.codes.delete(form.get('code') || '')
        if (decodeURIComponent(basic) !== `${this.clientId}:${this.clientSecret}`) return json(401, { error: 'invalid_client' })
        const challenge = createHash('sha256').update(form.get('code_verifier') || '').digest('base64url')
        if (!grant || grant.challenge !== challenge || grant.redirectUri !== form.get('redirect_uri')) return json(400, { error: 'invalid_grant' })
        const idToken = await new SignJWT({ ...grant.user, nonce: grant.nonce })
          .setProtectedHeader({ alg: 'RS256', kid: 'k' })
          .setIssuer(this.issuer)
          .setAudience(this.clientId)
          .setIssuedAt()
          .setExpirationTime('5m')
          .sign(privateKey)
        return json(200, { access_token: 'at', token_type: 'Bearer', expires_in: 300, id_token: idToken })
      }
      json(404, { error: 'not_found' })
    })
    await new Promise<void>((resolve) => this.server.listen(0, '127.0.0.1', resolve))
    this.issuer = `http://127.0.0.1:${(this.server.address() as AddressInfo).port}`
    return this
  }

  stop(): Promise<void> {
    return new Promise((resolve) => this.server.close(() => resolve()))
  }
}
