// Auth helpers for server components, server actions and route handlers.

import { cache } from 'react'
import { cookies, headers } from 'next/headers'
import { notFound, redirect } from 'next/navigation'
import { type Actor, recordAudit } from '../audit'
import { clientIp } from '../client-ip'
import { getPool } from '../db'
import { type Access, authorize } from './access'
import { authProvider, authenticate, hasSignInPage } from './index'
import { atLeast } from './roles'
import type { AuthResult, Role } from './types'

// One authentication per request, however many components ask.
export const getAuth = cache(async (): Promise<AuthResult> => {
  const [h, c] = await Promise.all([headers(), cookies()])
  return authenticate({ headers: h, cookie: (name) => c.get(name)?.value })
})

function redirectAway(auth: AuthResult): never {
  if (auth.status === 'setup_required') redirect('/setup')
  if (auth.status === 'unauthenticated' && hasSignInPage(authProvider())) redirect('/login')
  redirect('/denied')
}

// For pages: the caller's access (role and visible domains), or a redirect.
export async function requireViewer(): Promise<Access> {
  const auth = await getAuth()
  if (auth.status === 'ok') return authorize(auth.session)
  redirectAway(auth)
}

// For pages that need more than viewing. Someone signed in with too low a
// role sees "not found", which says nothing about what is there.
export async function requirePageRole(minimum: Role): Promise<Access> {
  const access = await requireViewer()
  if (!atLeast(access.role, minimum)) notFound()
  return access
}

// For actions and route handlers: null unless the caller has the role.
export async function getAccessWithRole(minimum: Role): Promise<Access | null> {
  const auth = await getAuth()
  return auth.status === 'ok' && atLeast(auth.session.role, minimum) ? authorize(auth.session) : null
}

export async function getAdminSession() {
  return (await getAccessWithRole('admin'))?.session ?? null
}

export async function currentActor(): Promise<Actor> {
  const [auth, h] = await Promise.all([getAuth(), headers()])
  const ip = clientIp(h)
  if (auth.status === 'ok') return { userId: auth.session.userId, email: auth.session.identity.email, ip }
  if (auth.status === 'forbidden') return { userId: null, email: auth.identity.email, ip }
  return { userId: null, email: null, ip }
}

// Audit entry for something the current caller did.
export async function audit(action: string, detail: Record<string, unknown> = {}, target?: string): Promise<void> {
  await recordAudit(getPool(), { action, actor: await currentActor(), target, detail })
}
