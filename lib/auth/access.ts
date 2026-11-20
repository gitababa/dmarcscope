// The one authorization function: what a signed-in person may do (their
// role) and which domains they may see. Every page gets its DomainScope from
// here, every query in lib/queries.ts requires one and filters by it, and the
// API and SCIM endpoints get theirs from lib/api-tokens.ts, which calls into
// the same resolution.
//
// Resolution (docs/enterprise.md, Domain permissions):
//   owner, admin      → every domain, always.
//   viewer            → their own domain_scopes row wins: 'all' → all domains,
//                       'limited' → their grants plus the grants of the
//                       'limited' groups they are in.
//                       No own row: a group row 'all' → all domains; otherwise
//                       the union of 'limited' groups' grants; no rows at all →
//                       access.domain_default ('all' unless an owner chose
//                       'none').
// Missing information is never read as "everything": a limited principal with
// no grants sees nothing, and 'none' makes "no rows" see nothing.

import type { Pool } from 'pg'
import { getPool } from '../db'
import { configStore } from '../settings'
import type { Role, Session } from './types'

const SCOPE = Symbol.for('dmarcscope.domain-scope')

export type DomainScope =
  | { readonly kind: 'all'; readonly [SCOPE]: true }
  | { readonly kind: 'domains'; readonly names: readonly string[]; readonly [SCOPE]: true }

export type Access = {
  session: Session
  role: Role
  domains: DomainScope
}

const ALL: DomainScope = Object.freeze({ kind: 'all', [SCOPE]: true } as const)

// A scope limited to these domains (an empty list sees nothing).
export function limitedTo(names: Iterable<string>): DomainScope {
  const unique = [...new Set([...names].map((n) => n.trim().toLowerCase()).filter(Boolean))].sort()
  return Object.freeze({ kind: 'domains', names: Object.freeze(unique), [SCOPE]: true } as const)
}

export function allDomains(): DomainScope {
  return ALL
}

// For bearer-authenticated machine endpoints (/api/cron/*), which act for the
// whole deployment rather than for a person.
export function machineScope(): DomainScope {
  return ALL
}

export function assertScope(scope: unknown): asserts scope is DomainScope {
  if (!scope || typeof scope !== 'object' || (scope as Record<symbol, unknown>)[SCOPE] !== true) {
    throw new Error('A query was called without a domain scope from lib/auth/access.ts')
  }
}

// The lower-cased domain names a scope allows, or null for every domain. What
// queries filter by.
export function scopeNames(scope: DomainScope): string[] | null {
  assertScope(scope)
  return scope.kind === 'all' ? null : [...scope.names]
}

export function scopeAllows(scope: DomainScope, domain: string): boolean {
  assertScope(scope)
  return scope.kind === 'all' || scope.names.includes(domain.trim().toLowerCase())
}

// The intersection of two scopes: what both allow. Never wider than either.
export function intersectScopes(a: DomainScope, b: DomainScope): DomainScope {
  assertScope(a)
  assertScope(b)
  if (a.kind === 'all') return b
  if (b.kind === 'all') return a
  const inB = new Set(b.names)
  return limitedTo(a.names.filter((n) => inB.has(n)))
}

export type ScopeRow = { kind: 'user' | 'group'; mode: 'all' | 'limited'; domains: string[] }

export type ScopeFacts = {
  role: Role
  // The person's own row, if any, and the rows of their groups (claim groups
  // and SCIM groups together).
  own: ScopeRow | null
  groups: ScopeRow[]
  defaultMode: 'all' | 'none'
}

// Pure: the rules above, nothing else.
export function resolveScope(f: ScopeFacts): DomainScope {
  if (f.role === 'owner' || f.role === 'admin') return ALL
  const limitedGroups = f.groups.filter((g) => g.mode === 'limited')
  const union = () => limitedTo([...(f.own?.domains ?? []), ...limitedGroups.flatMap((g) => g.domains)])
  if (f.own) return f.own.mode === 'all' ? ALL : union()
  if (f.groups.some((g) => g.mode === 'all')) return ALL
  if (limitedGroups.length > 0) return union()
  return f.defaultMode === 'none' ? limitedTo([]) : ALL
}

type Loaded = { own: ScopeRow | null; groups: ScopeRow[] }

// One query: the person's row and the rows of every group they are in.
// `claimGroups` come from the identity provider; SCIM memberships are read
// here, so a membership change applies on the person's next request.
export async function loadScopeRows(db: Pick<Pool, 'query'>, userId: number | null, claimGroups: string[]): Promise<Loaded> {
  const names = [...new Set(claimGroups.map((g) => g.toLowerCase()))]
  const { rows } = await db.query<{ kind: 'user' | 'group'; mode: 'all' | 'limited'; domains: string[] }>(
    `SELECT s.kind, s.mode,
            COALESCE(array_agg(g.domain) FILTER (WHERE g.domain IS NOT NULL), '{}') AS domains
       FROM domain_scopes s
       LEFT JOIN domain_grants g ON g.scope_id = s.id
      WHERE (s.kind = 'user' AND $1::bigint IS NOT NULL AND s.principal = $1::bigint::text)
         OR (s.kind = 'group' AND s.principal = ANY(
              $2::text[] || ARRAY(SELECT lower(gr.display_name) FROM groups gr
                                    JOIN group_members m ON m.group_id = gr.id WHERE m.user_id = $1::bigint)))
      GROUP BY s.id`,
    [userId, names]
  )
  return {
    own: rows.find((r) => r.kind === 'user') ?? null,
    groups: rows.filter((r) => r.kind === 'group'),
  }
}

export type ScopeLoader = (session: Session) => Promise<DomainScope>

export const loadScopeFor: ScopeLoader = async (session) => {
  // Roles that see everything need no lookup.
  if (session.role === 'owner' || session.role === 'admin') return ALL
  const defaultSetting = await configStore().get('access.domain_default')
  const { own, groups } = await loadScopeRows(getPool(), session.userId, session.identity.groups)
  return resolveScope({ role: session.role, own, groups, defaultMode: defaultSetting === 'none' ? 'none' : 'all' })
}

export async function authorize(session: Session, load: ScopeLoader = loadScopeFor): Promise<Access> {
  return { session, role: session.role, domains: await load(session) }
}
