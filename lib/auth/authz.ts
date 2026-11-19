// Access rules: which role an access rule gives an authenticated identity.
//
// Environment lists (as in 1.1.0; they cannot be edited in the panel):
//   ADMIN_EMAILS / ADMIN_GROUPS       → admin
//   ALLOWED_EMAILS                    → viewer
//   ALLOWED_EMAIL_DOMAINS             → viewer (anyone with an address at these domains)
//   ALLOWED_GROUPS                    → viewer (IdP group claim / proxy groups header)
//   AUTH_ALLOW_ANY_AUTHENTICATED=true → viewer for everyone the IdP lets through
//
// Database rules (access_rules): an email domain or a group → admin or viewer.
//
// The default is deny: being able to sign in at the identity provider does
// not by itself grant access. Rules never grant `owner`. How a rule's answer
// combines with the person's users row is in lib/auth/resolve.ts.

import { envBool, envList, type Env } from '../config'
import type { AccessRule } from '../settings/store'
import { higherRole } from './roles'
import type { Identity, Role } from './types'

function emailDomain(email: string): string {
  const at = email.lastIndexOf('@')
  return at === -1 ? '' : email.slice(at + 1)
}

function intersects(groups: string[], configured: string[]): boolean {
  if (configured.length === 0 || groups.length === 0) return false
  const set = new Set(configured)
  return groups.some((g) => set.has(g.toLowerCase()))
}

// The environment lists only.
export function resolveRole(identity: Identity, env: Env = process.env): Role | null {
  const email = identity.email.trim().toLowerCase()
  if (!email) return null

  if (envList(env.ADMIN_EMAILS).includes(email) || intersects(identity.groups, envList(env.ADMIN_GROUPS))) {
    return 'admin'
  }
  if (
    envList(env.ALLOWED_EMAILS).includes(email) ||
    envList(env.ALLOWED_EMAIL_DOMAINS).includes(emailDomain(email)) ||
    intersects(identity.groups, envList(env.ALLOWED_GROUPS)) ||
    envBool(env.AUTH_ALLOW_ANY_AUTHENTICATED)
  ) {
    return 'viewer'
  }
  return null
}

// The database rules only.
export function resolveRuleRole(identity: Identity, rules: readonly AccessRule[]): Role | null {
  const email = identity.email.trim().toLowerCase()
  if (!email) return null
  const domain = emailDomain(email)
  const groups = new Set(identity.groups.map((g) => g.toLowerCase()))
  let best: Role | null = null
  for (const rule of rules) {
    const match = rule.kind === 'email_domain' ? rule.value === domain : groups.has(rule.value)
    if (match) best = higherRole(best, rule.role)
  }
  return best
}

// Both: the best role any rule gives.
export function ruleRole(identity: Identity, env: Env, rules: readonly AccessRule[]): Role | null {
  return higherRole(resolveRole(identity, env), resolveRuleRole(identity, rules))
}

export function ruleGroups(rules: readonly AccessRule[]): string[] {
  return rules.filter((r) => r.kind === 'group').map((r) => r.value)
}

// The groups worth keeping from a sign-in: those an access rule mentions and
// those a domain scope is keyed on.
export function trackedGroups(cfg: { rules: readonly AccessRule[]; scopeGroups?: readonly string[] }): string[] {
  return [...new Set([...ruleGroups(cfg.rules), ...(cfg.scopeGroups ?? [])])]
}

// Identity providers can return hundreds of groups; only the ones some rule
// mentions are worth keeping in the session cookie. `extra` are the groups
// named by database rules.
export function relevantGroups(groups: string[], env: Env = process.env, extra: readonly string[] = []): string[] {
  const configured = new Set([...envList(env.ADMIN_GROUPS), ...envList(env.ALLOWED_GROUPS), ...extra.map((g) => g.toLowerCase())])
  if (configured.size === 0) return []
  return groups.filter((g) => configured.has(g.toLowerCase()))
}
