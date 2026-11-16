// The one authorization function: what a signed-in person may do (their
// role) and which domains they may see. Every page gets its DomainScope from
// here, and every query in lib/queries.ts requires one, so per-domain
// permissions (milestone 6) change this function, not every page.
//
// Today every role sees every domain.

import type { Role, Session } from './types'

const SCOPE = Symbol.for('dmarcscope.domain-scope')

export type DomainScope = { readonly kind: 'all'; readonly [SCOPE]: true }

export type Access = {
  session: Session
  role: Role
  domains: DomainScope
}

const ALL: DomainScope = Object.freeze({ kind: 'all', [SCOPE]: true } as const)

export function authorize(session: Session): Access {
  return { session, role: session.role, domains: ALL }
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
