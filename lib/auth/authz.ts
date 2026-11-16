// Authorization: maps an authenticated identity to a role, from configuration.
//
//   ADMIN_EMAILS / ADMIN_GROUPS       → admin  (may run DNS checks; implies viewer)
//   ALLOWED_EMAILS                    → viewer
//   ALLOWED_EMAIL_DOMAINS             → viewer (anyone with an address at these domains)
//   ALLOWED_GROUPS                    → viewer (IdP group claim / proxy groups header)
//   AUTH_ALLOW_ANY_AUTHENTICATED=true → viewer for everyone the IdP lets through
//
// The default is deny: being able to sign in at the identity provider does not
// by itself grant access. (A "Sign in with Google" client, for example, will
// happily authenticate any Google account.) Roles are recomputed on every
// request from these lists, so a list change applies as soon as the app runs
// with the new configuration. What the identity provider said at sign-in
// (email, groups) is a different matter: with AUTH_PROVIDER=oidc it is fixed
// in the session cookie until that expires — see SESSION_NOT_BEFORE.

import { envBool, envList, type Env } from '../config'
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

// Identity providers can return hundreds of groups; only the ones that affect
// authorization are worth keeping in the session cookie.
export function relevantGroups(groups: string[], env: Env = process.env): string[] {
  const configured = new Set([...envList(env.ADMIN_GROUPS), ...envList(env.ALLOWED_GROUPS)])
  if (configured.size === 0) return []
  return groups.filter((g) => configured.has(g.toLowerCase()))
}
