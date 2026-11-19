// Domain scopes managed in the panel: which viewers (or groups) are limited
// to which domains. Administrators and owners manage them; only viewers can be
// limited (an administrator always sees every domain, so a limit on one would
// promise something the product does not do).
//
// Every change is one transaction that re-reads the caller, writes the audit
// entry and bumps config_version, so every replica sees it on its next
// request; refusals are audited too.

import type { Pool, PoolClient } from 'pg'
import { type Actor, recordAudit, writeAudit } from './audit'
import { atLeast } from './auth/roles'
import type { Role } from './auth/types'
import { normalizeDomain } from './mail'

export type ScopeActor = Actor & { role: Role }
export type ScopeRefusalCode = 'not_allowed' | 'invalid' | 'not_found' | 'not_applicable'

export class ScopeRefusal extends Error {
  constructor(
    public code: ScopeRefusalCode,
    public field?: string
  ) {
    super(field ? `${code}:${field}` : code)
    this.name = 'ScopeRefusal'
  }
}

export const MAX_DOMAINS_PER_SCOPE = 500

export type ScopeInput = { mode: unknown; domains: string }

// "all" or "limited", and the domains (one per line, comma or space
// separated). A limited scope may be empty: it then sees nothing, on purpose.
export function parseScope(i: ScopeInput): { mode: 'all' | 'limited'; domains: string[] } {
  if (i.mode !== 'all' && i.mode !== 'limited') throw new ScopeRefusal('invalid', 'mode')
  const out: string[] = []
  for (const raw of i.domains.split(/[\s,;]+/).filter(Boolean)) {
    const d = normalizeDomain(raw)
    if (!d) throw new ScopeRefusal('invalid', 'domains')
    out.push(d)
  }
  const domains = [...new Set(out)]
  if (domains.length > MAX_DOMAINS_PER_SCOPE) throw new ScopeRefusal('invalid', 'domains')
  return { mode: i.mode, domains: i.mode === 'limited' ? domains : [] }
}

export const normalizeGroupName = (raw: string): string | null => {
  const g = raw.trim().toLowerCase()
  return g && g.length <= 300 && !/[\x00-\x1f\x7f]/.test(g) ? g : null
}

async function act<T>(
  db: Pool,
  actor: ScopeActor,
  action: string,
  target: string,
  fn: (c: PoolClient) => Promise<{ result: T; detail: Record<string, unknown> }>
): Promise<T> {
  try {
    if (!atLeast(actor.role, 'admin')) throw new ScopeRefusal('not_allowed')
    const client = await db.connect()
    try {
      await client.query('BEGIN')
      if (actor.userId != null) {
        const me = await client.query<{ status: string; role: Role }>(`SELECT status, role FROM users WHERE id = $1`, [actor.userId])
        if (me.rows[0]?.status !== 'active' || !atLeast(me.rows[0].role, 'admin')) throw new ScopeRefusal('not_allowed')
      }
      const { result, detail } = await fn(client)
      await client.query('UPDATE config_version SET version = version + 1')
      await writeAudit(client, { action, actor, target, detail })
      await client.query('COMMIT')
      return result
    } catch (err) {
      await client.query('ROLLBACK').catch(() => {})
      throw err
    } finally {
      client.release()
    }
  } catch (err) {
    if (err instanceof ScopeRefusal) {
      await recordAudit(db, { action: 'action_refused', actor, target, detail: { action, reason: err.code, ...(err.field ? { field: err.field } : {}) } })
    }
    throw err
  }
}

async function writeScope(c: PoolClient, kind: 'user' | 'group', principal: string, v: { mode: 'all' | 'limited'; domains: string[] }, actor: ScopeActor) {
  const { rows } = await c.query<{ id: string }>(
    `INSERT INTO domain_scopes (kind, principal, mode, updated_by) VALUES ($1, $2, $3, $4)
     ON CONFLICT (kind, principal) DO UPDATE SET mode = EXCLUDED.mode, updated_at = NOW(), updated_by = EXCLUDED.updated_by
     RETURNING id`,
    [kind, principal, v.mode, actor.userId]
  )
  const id = rows[0].id
  await c.query(`DELETE FROM domain_grants WHERE scope_id = $1`, [id])
  if (v.domains.length) await c.query(`INSERT INTO domain_grants (scope_id, domain) SELECT $1, UNNEST($2::text[])`, [id, v.domains])
}

// A person's own scope. Refused for administrators and owners.
export async function setUserScope(db: Pool, actor: ScopeActor, userId: number, input: ScopeInput): Promise<void> {
  await act(db, actor, 'domain_scope_changed', `user:${userId}`, async (c) => {
    const v = parseScope(input)
    const u = (await c.query<{ role: Role; email: string }>(`SELECT role, email FROM users WHERE id = $1 FOR UPDATE`, [userId])).rows[0]
    if (!u) throw new ScopeRefusal('not_found')
    if (u.role !== 'viewer') throw new ScopeRefusal('not_applicable')
    await writeScope(c, 'user', String(userId), v, actor)
    return { result: undefined, detail: { email: u.email, mode: v.mode, domains: v.domains } }
  })
}

// Back to "no opinion": the groups and access.domain_default decide again.
export async function clearUserScope(db: Pool, actor: ScopeActor, userId: number): Promise<void> {
  await act(db, actor, 'domain_scope_cleared', `user:${userId}`, async (c) => {
    const { rowCount } = await c.query(`DELETE FROM domain_scopes WHERE kind = 'user' AND principal = $1`, [String(userId)])
    return { result: undefined, detail: { had_scope: Boolean(rowCount) } }
  })
}

export async function setGroupScope(db: Pool, actor: ScopeActor, groupName: string, input: ScopeInput): Promise<void> {
  const name = normalizeGroupName(groupName)
  await act(db, actor, 'domain_scope_changed', `group:${name ?? '?'}`, async (c) => {
    if (!name) throw new ScopeRefusal('invalid', 'group')
    const v = parseScope(input)
    await writeScope(c, 'group', name, v, actor)
    return { result: undefined, detail: { group: name, mode: v.mode, domains: v.domains } }
  })
}

export async function clearGroupScope(db: Pool, actor: ScopeActor, groupName: string): Promise<void> {
  const name = normalizeGroupName(groupName)
  await act(db, actor, 'domain_scope_cleared', `group:${name ?? '?'}`, async (c) => {
    if (!name) throw new ScopeRefusal('invalid', 'group')
    const { rowCount } = await c.query(`DELETE FROM domain_scopes WHERE kind = 'group' AND principal = $1`, [name])
    return { result: undefined, detail: { group: name, had_scope: Boolean(rowCount) } }
  })
}

// ---------- reading ----------

type Q = Pick<Pool, 'query'>

export type StoredScope = { mode: 'all' | 'limited'; domains: string[] }

export async function getUserScope(db: Q, userId: number): Promise<StoredScope | null> {
  const { rows } = await db.query<{ mode: 'all' | 'limited'; domains: string[] }>(
    `SELECT s.mode, COALESCE(array_agg(g.domain ORDER BY g.domain) FILTER (WHERE g.domain IS NOT NULL), '{}') AS domains
       FROM domain_scopes s LEFT JOIN domain_grants g ON g.scope_id = s.id
      WHERE s.kind = 'user' AND s.principal = $1 GROUP BY s.id`,
    [String(userId)]
  )
  return rows[0] ?? null
}

export type GroupRow = { name: string; scope: StoredScope | null; members: number; in_rules: boolean; from_scim: boolean }

// Every group the deployment knows of: SCIM groups, groups named by access
// rules and groups with a scope.
export async function listGroups(db: Q): Promise<GroupRow[]> {
  const { rows } = await db.query<{ name: string; mode: 'all' | 'limited' | null; domains: string[]; members: string; in_rules: boolean; from_scim: boolean }>(
    `WITH names AS (
       SELECT lower(display_name) AS name FROM groups
       UNION SELECT value FROM access_rules WHERE kind = 'group'
       UNION SELECT principal FROM domain_scopes WHERE kind = 'group'
     )
     SELECT n.name,
            s.mode,
            COALESCE((SELECT array_agg(g.domain ORDER BY g.domain) FROM domain_grants g WHERE g.scope_id = s.id), '{}') AS domains,
            (SELECT count(*) FROM group_members m JOIN groups gr ON gr.id = m.group_id WHERE lower(gr.display_name) = n.name) AS members,
            EXISTS (SELECT 1 FROM access_rules r WHERE r.kind = 'group' AND r.value = n.name) AS in_rules,
            EXISTS (SELECT 1 FROM groups gr WHERE lower(gr.display_name) = n.name) AS from_scim
       FROM names n LEFT JOIN domain_scopes s ON s.kind = 'group' AND s.principal = n.name
      ORDER BY n.name`
  )
  return rows.map((r) => ({
    name: r.name,
    scope: r.mode ? { mode: r.mode, domains: r.domains } : null,
    members: Number(r.members),
    in_rules: r.in_rules,
    from_scim: r.from_scim,
  }))
}

// The groups a person is in through SCIM, with what each adds.
export async function listUserGroups(db: Q, userId: number): Promise<Array<{ name: string; scope: StoredScope | null }>> {
  const { rows } = await db.query<{ name: string; mode: 'all' | 'limited' | null; domains: string[] }>(
    `SELECT lower(gr.display_name) AS name, s.mode,
            COALESCE((SELECT array_agg(g.domain ORDER BY g.domain) FROM domain_grants g WHERE g.scope_id = s.id), '{}') AS domains
       FROM group_members m JOIN groups gr ON gr.id = m.group_id
       LEFT JOIN domain_scopes s ON s.kind = 'group' AND s.principal = lower(gr.display_name)
      WHERE m.user_id = $1 ORDER BY 1`,
    [userId]
  )
  return rows.map((r) => ({ name: r.name, scope: r.mode ? { mode: r.mode, domains: r.domains } : null }))
}
