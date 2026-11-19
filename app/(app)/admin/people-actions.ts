'use server'

// People and access-rule actions. Each one re-checks the caller's role (the
// page that shows a form is not a permission check); lib/people.ts holds the
// rules and writes the audit entries, including for refusals.

import { redirect } from 'next/navigation'
import { revalidatePath } from 'next/cache'
import { audit, currentActor, getAccessWithRole } from '@/lib/auth/server'
import { getPool } from '@/lib/db'
import {
  type PeopleActor,
  Refusal,
  addRule,
  approveRequest,
  changeRole,
  deleteRule,
  inviteUser,
  rejectRequest,
  removeUser,
  setDisabled,
  signOutEverywhere,
} from '@/lib/people'

async function caller(action: string): Promise<PeopleActor> {
  const access = await getAccessWithRole('admin')
  if (!access) {
    await audit('action_refused', { action, reason: 'not_allowed' })
    redirect('/denied')
  }
  return { ...(await currentActor()), role: access.role }
}

// Where to go afterwards: a page of the admin area, nothing else.
function backTo(form: FormData, fallback: string): string {
  const raw = String(form.get('back') || '')
  return /^\/admin(\/[a-z0-9/_-]*)?(\?[a-zA-Z0-9=&%._-]*)?$/.test(raw) && !raw.includes('//') ? raw : fallback
}

function withParam(path: string, key: string, value: string): string {
  return `${path}${path.includes('?') ? '&' : '?'}${key}=${encodeURIComponent(value)}`
}

const id = (form: FormData) => {
  const n = Number(String(form.get('id') || ''))
  return Number.isSafeInteger(n) && n > 0 ? n : 0
}

async function run(
  form: FormData,
  action: string,
  fallback: string,
  done: string,
  fn: (actor: PeopleActor) => Promise<unknown>,
  after?: string
): Promise<never> {
  const actor = await caller(action)
  const back = backTo(form, fallback)
  try {
    await fn(actor)
  } catch (err) {
    if (err instanceof Refusal) redirect(withParam(back, 'error', err.code))
    throw err
  }
  revalidatePath('/admin', 'layout')
  redirect(withParam(after ?? back, 'done', done))
}

export async function inviteAction(form: FormData): Promise<void> {
  await run(form, 'user_invited', '/admin/users', 'invited', (a) =>
    inviteUser(getPool(), a, { email: String(form.get('email') || '').slice(0, 320), role: form.get('role') })
  )
}

export async function approveAction(form: FormData): Promise<void> {
  await run(form, 'request_approved', '/admin/users', 'approved', (a) => approveRequest(getPool(), a, id(form), form.get('role')))
}

export async function rejectAction(form: FormData): Promise<void> {
  await run(form, 'request_rejected', '/admin/users', 'rejected', (a) => rejectRequest(getPool(), a, id(form)))
}

export async function changeRoleAction(form: FormData): Promise<void> {
  await run(form, 'role_changed', `/admin/users/${id(form)}`, 'role', (a) => changeRole(getPool(), a, id(form), form.get('role')))
}

export async function disableAction(form: FormData): Promise<void> {
  await run(form, 'user_disabled', `/admin/users/${id(form)}`, 'disabled', (a) => setDisabled(getPool(), a, id(form), true))
}

export async function enableAction(form: FormData): Promise<void> {
  await run(form, 'user_enabled', `/admin/users/${id(form)}`, 'enabled', (a) => setDisabled(getPool(), a, id(form), false))
}

export async function signOutEverywhereAction(form: FormData): Promise<void> {
  await run(form, 'sessions_revoked', `/admin/users/${id(form)}`, 'signed_out', (a) => signOutEverywhere(getPool(), a, id(form)))
}

export async function removeAction(form: FormData): Promise<void> {
  // The confirmation step is a separate form that carries confirm=yes.
  if (form.get('confirm') !== 'yes') redirect(`/admin/users/${id(form)}?confirm=remove`)
  // Afterwards the person's page no longer exists: back to the list.
  await run(form, 'user_removed', `/admin/users/${id(form)}`, 'removed', (a) => removeUser(getPool(), a, id(form)), '/admin/users')
}

export async function addRuleAction(form: FormData): Promise<void> {
  await run(form, 'rule_added', '/admin/rules', 'added', (a) =>
    addRule(getPool(), a, { kind: form.get('kind'), value: String(form.get('value') || '').slice(0, 300), role: form.get('role') })
  )
}

export async function deleteRuleAction(form: FormData): Promise<void> {
  await run(form, 'rule_deleted', '/admin/rules', 'deleted', (a) => deleteRule(getPool(), a, id(form)))
}
