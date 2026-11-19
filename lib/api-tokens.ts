// API tokens (read-only JSON API) and the SCIM token.
//
// - A token is `dsa_` (API) or `dss_` (SCIM) plus 32 random bytes, base64url.
//   Only its SHA-256 is stored, so a database copy gives nobody a token; the
//   token is shown once, when it is made. The hash is of a high-entropy value,
//   so a fast hash is the right one and the lookup is by hash.
// - The token's own domain limit (mode and domains) is on its row. Its
//   creator must still be an active administrator or owner when it is used,
//   otherwise it fails: a token is never wider than the person who made it,
//   and demoting or disabling that person ends it.
// - Unknown, malformed, expired, revoked and creator-less tokens are one and
//   the same answer (null), so a caller learns nothing about which it was.
// - Only a header carries a token (never a URL).

import { createHash, randomBytes } from 'node:crypto'
import type { Pool, PoolClient } from 'pg'
import { type Actor, recordAudit, writeAudit } from './audit'
import { type DomainScope, allDomains, limitedTo } from './auth/access'
import { atLeast } from './auth/roles'
import type { Role } from './auth/types'
import { normalizeDomain } from './mail'

export const API_SCOPES = ['domains:read', 'reports:read', 'dns:read'] as const
export type ApiScope = (typeof API_SCOPES)[number]
export type TokenKind = 'api' | 'scim'

export const MAX_ACTIVE_TOKENS = 50
export const MAX_EXPIRY_DAYS = 365
export const DEFAULT_EXPIRY_DAYS = 90

const PREFIX: Record<TokenKind, string> = { api: 'dsa_', scim: 'dss_' }
const SHAPE = /^(dsa|dss)_[A-Za-z0-9_-]{43}$/

export const hashToken = (token: string) => createHash('sha256').update(token).digest('hex')

export function newToken(kind: TokenKind): { token: string; prefix: string; hash: string } {
  const token = PREFIX[kind] + randomBytes(32).toString('base64url')
  return { token, prefix: token.slice(0, 8), hash: hashToken(token) }
}

// "Bearer <token>" and nothing else.
export function bearer(header: string | null | undefined): string | null {
  if (!header) return null
  const m = /^Bearer ([^\s]+)$/.exec(header)
  return m && SHAPE.test(m[1]) ? m[1] : null
}

export type TokenActor = Actor & { role: Role }
export type TokenRefusalCode = 'not_allowed' | 'invalid' | 'not_found' | 'limit'

export class TokenRefusal extends Error {
  constructor(
    public code: TokenRefusalCode,
    public field?: string
  ) {
    super(field ? `${code}:${field}` : code)
    this.name = 'TokenRefusal'
  }
}

export type TokenInput = { name: string; scopes: string[]; mode: unknown; domains: string; expiresInDays: string }

export type ValidToken = { name: string; scopes: ApiScope[]; mode: 'all' | 'limited'; domains: string[]; expiresInDays: number }

export function validateToken(i: TokenInput): ValidToken {
  const name = i.name.trim()
  if (!name || name.length > 100 || /[\x00-\x1f\x7f]/.test(name)) throw new TokenRefusal('invalid', 'name')
  const scopes = [...new Set(i.scopes)]
  if (scopes.length === 0 || !scopes.every((s): s is ApiScope => (API_SCOPES as readonly string[]).includes(s))) throw new TokenRefusal('invalid', 'scopes')
  if (i.mode !== 'all' && i.mode !== 'limited') throw new TokenRefusal('invalid', 'mode')
  const domains: string[] = []
  for (const raw of i.domains.split(/[\s,;]+/).filter(Boolean)) {
    const d = normalizeDomain(raw)
    if (!d) throw new TokenRefusal('invalid', 'domains')
    domains.push(d)
  }
  const unique = [...new Set(domains)]
  if (unique.length > 500) throw new TokenRefusal('invalid', 'domains')
  const t = i.expiresInDays.trim()
  const days = t === '' ? DEFAULT_EXPIRY_DAYS : /^\d{1,4}$/.test(t) ? Number(t) : NaN
  if (!Number.isInteger(days) || days < 1 || days > MAX_EXPIRY_DAYS) throw new TokenRefusal('invalid', 'expires')
  return { name, scopes: scopes as ApiScope[], mode: i.mode, domains: i.mode === 'limited' ? unique : [], expiresInDays: days }
}

async function act<T>(
  db: Pool,
  actor: TokenActor,
  minimum: Role,
  action: string,
  target: string,
  fn: (c: PoolClient) => Promise<{ result: T; detail: Record<string, unknown>; target?: string }>
): Promise<T> {
  try {
    if (!atLeast(actor.role, minimum)) throw new TokenRefusal('not_allowed')
    const client = await db.connect()
    try {
      await client.query('BEGIN')
      if (actor.userId != null) {
        const me = await client.query<{ status: string; role: Role }>(`SELECT status, role FROM users WHERE id = $1`, [actor.userId])
        if (me.rows[0]?.status !== 'active' || !atLeast(me.rows[0].role, minimum)) throw new TokenRefusal('not_allowed')
      }
      const out = await fn(client)
      await writeAudit(client, { action, actor, target: out.target ?? target, detail: out.detail })
      await client.query('COMMIT')
      return out.result
    } catch (err) {
      await client.query('ROLLBACK').catch(() => {})
      throw err
    } finally {
      client.release()
    }
  } catch (err) {
    if (err instanceof TokenRefusal) {
      await recordAudit(db, { action: 'action_refused', actor, target, detail: { action, reason: err.code, ...(err.field ? { field: err.field } : {}) } })
    }
    throw err
  }
}

// An API token. The token is returned once, here, and nowhere else.
export async function createApiToken(db: Pool, actor: TokenActor, input: TokenInput): Promise<{ id: number; token: string }> {
  return act(db, actor, 'admin', 'api_token_created', 'api_token', async (c) => {
    const v = validateToken(input)
    if (actor.userId == null) throw new TokenRefusal('not_allowed')
    const active = await c.query<{ n: string }>(`SELECT count(*) AS n FROM api_tokens WHERE kind = 'api' AND revoked_at IS NULL AND expires_at > NOW()`)
    if (Number(active.rows[0].n) >= MAX_ACTIVE_TOKENS) throw new TokenRefusal('limit')
    const t = newToken('api')
    const { rows } = await c.query<{ id: string }>(
      `INSERT INTO api_tokens (kind, name, prefix, token_hash, scopes, domain_mode, domains, created_by, expires_at)
       VALUES ('api', $1, $2, $3, $4, $5, $6, $7, NOW() + make_interval(days => $8::int)) RETURNING id`,
      [v.name, t.prefix, t.hash, v.scopes, v.mode, v.domains, actor.userId, v.expiresInDays]
    )
    const id = Number(rows[0].id)
    return { result: { id, token: t.token }, detail: { name: v.name, scopes: v.scopes, mode: v.mode, domains: v.domains, expires_in_days: v.expiresInDays }, target: `api_token:${id}` }
  })
}

// The SCIM token: it can create and disable people, so only an owner makes it,
// and making a new one ends the old.
export async function createScimToken(db: Pool, actor: TokenActor, nameInput: string, expiresInDays = '365'): Promise<{ id: number; token: string }> {
  return act(db, actor, 'owner', 'scim_token_created', 'scim_token', async (c) => {
    const name = nameInput.trim()
    if (!name || name.length > 100 || /[\x00-\x1f\x7f]/.test(name)) throw new TokenRefusal('invalid', 'name')
    const days = /^\d{1,4}$/.test(expiresInDays.trim()) ? Number(expiresInDays) : NaN
    if (!Number.isInteger(days) || days < 1 || days > MAX_EXPIRY_DAYS) throw new TokenRefusal('invalid', 'expires')
    if (actor.userId == null) throw new TokenRefusal('not_allowed')
    await c.query(`UPDATE api_tokens SET revoked_at = NOW() WHERE kind = 'scim' AND revoked_at IS NULL`)
    const t = newToken('scim')
    const { rows } = await c.query<{ id: string }>(
      `INSERT INTO api_tokens (kind, name, prefix, token_hash, scopes, domain_mode, domains, created_by, expires_at)
       VALUES ('scim', $1, $2, $3, '{}', 'limited', '{}', $4, NOW() + make_interval(days => $5::int)) RETURNING id`,
      [name, t.prefix, t.hash, actor.userId, days]
    )
    const id = Number(rows[0].id)
    return { result: { id, token: t.token }, detail: { name, expires_in_days: days }, target: `scim_token:${id}` }
  })
}

export async function revokeToken(db: Pool, actor: TokenActor, id: number): Promise<void> {
  await act(db, actor, 'admin', 'api_token_revoked', `api_token:${id}`, async (c) => {
    const { rows } = await c.query<{ name: string; kind: TokenKind }>(
      `UPDATE api_tokens SET revoked_at = NOW() WHERE id = $1 AND revoked_at IS NULL RETURNING name, kind`,
      [id]
    )
    if (!rows[0]) throw new TokenRefusal('not_found')
    // A SCIM token may only be ended by an owner.
    if (rows[0].kind === 'scim' && !atLeast(actor.role, 'owner')) throw new TokenRefusal('not_allowed')
    return { result: undefined, detail: { name: rows[0].name, kind: rows[0].kind } }
  })
}

export type TokenRow = {
  id: number
  kind: TokenKind
  name: string
  prefix: string
  scopes: string[]
  domain_mode: 'all' | 'limited'
  domains: string[]
  created_at: string
  expires_at: string
  last_used_at: string | null
  revoked_at: string | null
  created_by_email: string | null
  state: 'active' | 'expired' | 'revoked'
}

export async function listTokens(db: Pick<Pool, 'query'>, kind: TokenKind): Promise<TokenRow[]> {
  const { rows } = await db.query<Omit<TokenRow, 'id' | 'state'> & { id: string; active: boolean }>(
    `SELECT t.id, t.kind, t.name, t.prefix, t.scopes, t.domain_mode, t.domains, t.created_at, t.expires_at, t.last_used_at, t.revoked_at,
            u.email AS created_by_email, (t.revoked_at IS NULL AND t.expires_at > NOW()) AS active
       FROM api_tokens t LEFT JOIN users u ON u.id = t.created_by
      WHERE t.kind = $1 ORDER BY t.created_at DESC LIMIT 100`,
    [kind]
  )
  return rows.map((r) => ({ ...r, id: Number(r.id), state: r.revoked_at ? 'revoked' : r.active ? 'active' : 'expired' }))
}

export type TokenAuth = { id: number; name: string; kind: TokenKind; scopes: ApiScope[]; domains: DomainScope; creatorId: number }

// The token a request carries, or null. Never says why not.
export async function authenticateToken(db: Pool, header: string | null | undefined, kind: TokenKind): Promise<TokenAuth | null> {
  const token = bearer(header)
  if (!token || !token.startsWith(PREFIX[kind])) return null
  const { rows } = await db.query<{
    id: string
    name: string
    scopes: string[]
    domain_mode: 'all' | 'limited'
    domains: string[]
    created_by: string
    role: Role
    status: string
  }>(
    `SELECT t.id, t.name, t.scopes, t.domain_mode, t.domains, t.created_by, u.role, u.status
       FROM api_tokens t JOIN users u ON u.id = t.created_by
      WHERE t.token_hash = $1 AND t.kind = $2 AND t.revoked_at IS NULL AND t.expires_at > NOW()`,
    [hashToken(token), kind]
  )
  const r = rows[0]
  if (!r || r.status !== 'active' || !atLeast(r.role, 'admin')) return null
  // Best effort, at most once a minute: a failure here must not fail the call.
  db.query(`UPDATE api_tokens SET last_used_at = NOW() WHERE id = $1 AND (last_used_at IS NULL OR last_used_at < NOW() - INTERVAL '1 minute')`, [r.id]).catch(() => {})
  const known = (r.scopes as string[]).filter((s): s is ApiScope => (API_SCOPES as readonly string[]).includes(s))
  return {
    id: Number(r.id),
    name: r.name,
    kind,
    scopes: known,
    domains: r.domain_mode === 'all' ? allDomains() : limitedTo(r.domains),
    creatorId: Number(r.created_by),
  }
}
