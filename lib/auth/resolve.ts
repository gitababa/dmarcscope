// From "the provider says this is X" to "X may come in, with this role".
//
// Order of checks, on every request:
//   1. a disabled user is refused, whatever any rule says;
//   2. a session issued before the user's sessions_valid_after is refused
//      (they have to sign in again);
//   3. the role is the higher of the role assigned to the user (setup wizard,
//      an administrator, the settings import) and the best role any access
//      rule gives them now (environment lists and database rules);
//   4. no role: a person seen for the first time is recorded as a pending
//      request an administrator can approve, and refused.
//
// Rule-admitted people are re-evaluated every time, so removing a rule (or
// an address from ADMIN_EMAILS) removes the access it gave, as in 1.1.0.

import type { Env } from '../config'
import { ruleRole } from './authz'
import type { Directory, UserRow, UserSource } from './directory'
import { higherRole } from './roles'
import type { AuthProviderName, AuthResult, Identity } from './types'

export type SessionFacts = {
  // From a session cookie: when it was issued (seconds) and which user it
  // was issued to (absent in cookies from before 2.0).
  issuedAt?: number
  userId?: number
}

function sourceFor(provider: AuthProviderName): UserSource {
  return provider === 'proxy-jwt' || provider === 'proxy-header' ? 'proxy' : provider === 'local' ? 'local' : 'oidc'
}

export async function resolveAccess(
  identity: Identity,
  provider: AuthProviderName,
  facts: SessionFacts,
  env: Env,
  dir: Directory
): Promise<AuthResult> {
  let row: UserRow | null
  if (facts.userId != null) {
    row = await dir.findById(facts.userId)
    // A cookie for a user that no longer exists, or whose address changed,
    // is not a session any more.
    if (!row || row.email !== identity.email.toLowerCase()) return { status: 'unauthenticated' }
  } else {
    row = await dir.findByEmail(identity.email)
  }

  if (row?.status === 'disabled') return { status: 'forbidden', identity }

  if (row?.sessions_valid_after && facts.issuedAt != null) {
    const cutoff = Date.parse(row.sessions_valid_after)
    // Unparsable means "could not find out", which is not "no cut-off".
    if (Number.isNaN(cutoff) || facts.issuedAt * 1000 < cutoff) return { status: 'unauthenticated' }
  }

  const { rules } = await dir.config()
  const fromRules = ruleRole(identity, env, rules)
  const assigned = row && row.status === 'active' && row.role_source === 'assigned' ? row.role : null
  const role = higherRole(assigned, fromRules)

  if (!role) {
    if (!row) {
      const created = await dir.requestAccess(identity, sourceFor(provider))
      if (created) {
        await dir.audit({
          action: 'access_requested',
          actor: { userId: created.id, email: created.email, ip: null },
          target: `user:${created.id}`,
          detail: { provider },
        })
      }
    }
    return { status: 'forbidden', identity }
  }

  if (!row) {
    row = await dir.admit(identity, role, sourceFor(provider))
    // Lost a race with another request that created the row first: decide
    // on what is actually stored.
    if (row.status !== 'active' || row.role_source !== 'rule') return resolveAccess(identity, provider, facts, env, dir)
    await dir.audit({
      action: 'user_created',
      actor: { userId: row.id, email: row.email, ip: null },
      target: `user:${row.id}`,
      detail: { role, by: 'access_rule', provider },
    })
  } else if (row.role_source === 'rule' && (row.status === 'pending' || row.role !== fromRules) && fromRules) {
    await dir.syncRuleRole(row.id, fromRules)
  }

  return {
    status: 'ok',
    session: { identity: { ...identity, name: identity.name ?? row.name ?? undefined }, role, userId: row.id },
  }
}
