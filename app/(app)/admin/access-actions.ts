'use server'

// Domain scopes, API tokens and the SCIM token (administrators; the SCIM token
// is the owner's). Each re-checks the caller's role; lib/access-admin.ts and
// lib/api-tokens.ts hold the rules and write the audit entries, refusals too.

import { redirect } from 'next/navigation'
import { revalidatePath } from 'next/cache'
import { ScopeRefusal, clearGroupScope, clearUserScope, setGroupScope, setUserScope } from '@/lib/access-admin'
import { TokenRefusal, createApiToken, createScimToken, revokeToken } from '@/lib/api-tokens'
import { audit, currentActor, getAccessWithRole } from '@/lib/auth/server'
import type { Role } from '@/lib/auth/types'
import { getPool } from '@/lib/db'

async function actorFor(action: string, minimum: Role) {
  const access = await getAccessWithRole(minimum)
  if (!access) {
    await audit('action_refused', { action, reason: 'not_allowed' })
    redirect('/denied')
  }
  return { ...(await currentActor()), role: access.role }
}

const text = (form: FormData, name: string, max = 2000) => {
  const v = form.get(name)
  return typeof v === 'string' ? v.slice(0, max) : ''
}

const idOf = (form: FormData, name = 'id'): number => {
  const n = Number(text(form, name, 20))
  return Number.isSafeInteger(n) && n > 0 ? n : 0
}

// ---------- domain scopes ----------

async function scoped(action: string, ok: string, fail: string, fn: (a: Awaited<ReturnType<typeof actorFor>>) => Promise<void>): Promise<never> {
  const actor = await actorFor(action, 'admin')
  try {
    await fn(actor)
  } catch (err) {
    if (err instanceof ScopeRefusal) redirect(`${fail}${fail.includes('?') ? '&' : '?'}error=${err.code}${err.field ? `&field=${err.field}` : ''}`)
    throw err
  }
  revalidatePath('/admin/groups')
  revalidatePath('/admin/users')
  redirect(ok)
}

export async function setUserScopeAction(form: FormData): Promise<void> {
  const id = idOf(form)
  const back = `/admin/users/${id}`
  await scoped('domain_scope_changed', `${back}?done=scope_saved`, back, (a) => setUserScope(getPool(), a, id, { mode: form.get('mode'), domains: text(form, 'domains') }))
}

export async function clearUserScopeAction(form: FormData): Promise<void> {
  const id = idOf(form)
  const back = `/admin/users/${id}`
  await scoped('domain_scope_cleared', `${back}?done=scope_cleared`, back, (a) => clearUserScope(getPool(), a, id))
}

export async function setGroupScopeAction(form: FormData): Promise<void> {
  await scoped('domain_scope_changed', '/admin/groups?done=scope_saved', '/admin/groups', (a) =>
    setGroupScope(getPool(), a, text(form, 'group', 301), { mode: form.get('mode'), domains: text(form, 'domains') })
  )
}

export async function clearGroupScopeAction(form: FormData): Promise<void> {
  await scoped('domain_scope_cleared', '/admin/groups?done=scope_cleared', '/admin/groups', (a) => clearGroupScope(getPool(), a, text(form, 'group', 301)))
}

// ---------- tokens ----------

export type TokenState = { error?: string; token?: string; name?: string }

// The token is in the returned state once, for the page to show; it is not in
// a URL, a cookie or the database.
export async function createApiTokenAction(_prev: TokenState, form: FormData): Promise<TokenState> {
  const actor = await actorFor('api_token_created', 'admin')
  try {
    const r = await createApiToken(getPool(), actor, {
      name: text(form, 'name', 101),
      scopes: form.getAll('scopes').map(String),
      mode: form.get('mode'),
      domains: text(form, 'domains'),
      expiresInDays: text(form, 'expires', 5),
    })
    revalidatePath('/admin/api')
    return { token: r.token, name: text(form, 'name', 100) }
  } catch (err) {
    if (err instanceof TokenRefusal) return { error: err.field ? `${err.code}:${err.field}` : err.code }
    throw err
  }
}

export async function createScimTokenAction(_prev: TokenState, form: FormData): Promise<TokenState> {
  const actor = await actorFor('scim_token_created', 'owner')
  try {
    const r = await createScimToken(getPool(), actor, text(form, 'name', 101), text(form, 'expires', 5) || '365')
    revalidatePath('/admin/api')
    return { token: r.token, name: text(form, 'name', 100) }
  } catch (err) {
    if (err instanceof TokenRefusal) return { error: err.field ? `${err.code}:${err.field}` : err.code }
    throw err
  }
}

export async function revokeTokenAction(form: FormData): Promise<void> {
  const actor = await actorFor('api_token_revoked', 'admin')
  try {
    await revokeToken(getPool(), actor, idOf(form))
  } catch (err) {
    if (err instanceof TokenRefusal) redirect(`/admin/api?error=${err.code}`)
    throw err
  }
  revalidatePath('/admin/api')
  redirect('/admin/api?done=revoked')
}
