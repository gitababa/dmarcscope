'use server'

// Mailbox and monitored-domain actions (administrators). Each re-checks the
// caller's role; lib/mail.ts holds the rules and writes the audit entries,
// including for refusals.

import { redirect } from 'next/navigation'
import { revalidatePath } from 'next/cache'
import { audit, currentActor, getAccessWithRole } from '@/lib/auth/server'
import { getPool } from '@/lib/db'
import {
  type MailActor,
  type MailboxInput,
  MailRefusal,
  addDomain,
  createMailbox,
  deleteMailbox,
  removeDomain,
  requestJob,
  setMailboxEnabled,
  updateMailbox,
} from '@/lib/mail'

async function admin(action: string): Promise<MailActor> {
  const access = await getAccessWithRole('admin')
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

const idOf = (form: FormData): number => {
  const n = Number(text(form, 'id', 20))
  return Number.isSafeInteger(n) && n > 0 ? n : 0
}

// Where to go back to: only our own admin pages.
function back(form: FormData, fallback: string): string {
  const b = text(form, 'back', 200)
  return /^\/admin\/(mail(\/\d+)?|domains)$/.test(b) ? b : fallback
}

async function run<T>(action: string, ok: string | ((result: T) => string), fail: string, fn: (actor: MailActor) => Promise<T>): Promise<never> {
  const actor = await admin(action)
  let result: T
  try {
    result = await fn(actor)
  } catch (err) {
    if (err instanceof MailRefusal) {
      redirect(`${fail}${fail.includes('?') ? '&' : '?'}error=${err.code}${err.field ? `&field=${err.field}` : ''}`)
    }
    throw err
  }
  revalidatePath('/admin/mail')
  redirect(typeof ok === 'function' ? ok(result) : ok)
}

function mailboxInput(form: FormData): MailboxInput {
  return {
    name: text(form, 'name', 101),
    kind: form.get('kind'),
    host: text(form, 'host', 300),
    port: text(form, 'port', 10),
    security: form.get('security'),
    username: text(form, 'username', 321),
    tenantId: text(form, 'tenant_id', 300),
    clientId: text(form, 'client_id', 100),
    secret: text(form, 'secret', 20001),
    folder: text(form, 'folder', 201),
    processedFolder: text(form, 'processed_folder', 201),
    invalidFolder: text(form, 'invalid_folder', 201),
    intervalMinutes: text(form, 'interval_minutes', 10),
    enabled: form.get('enabled') === '1',
  }
}

export async function createMailboxAction(form: FormData): Promise<void> {
  const kind = String(form.get('kind') ?? 'imap').replace(/[^a-z]/g, '').slice(0, 20)
  await run('mailbox_created', (id: number) => `/admin/mail/${id}?done=created`, `/admin/mail?new=${kind}`, (a) => createMailbox(getPool(), a, mailboxInput(form)))
}

export async function updateMailboxAction(form: FormData): Promise<void> {
  const id = idOf(form)
  await run('mailbox_updated', `/admin/mail/${id}?done=saved`, `/admin/mail/${id}`, (a) => updateMailbox(getPool(), a, id, mailboxInput(form)))
}

export async function toggleMailboxAction(form: FormData): Promise<void> {
  const id = idOf(form)
  const enabled = form.get('enabled') === '1'
  const to = back(form, `/admin/mail/${id}`)
  await run(enabled ? 'mailbox_enabled' : 'mailbox_disabled', `${to}?done=${enabled ? 'enabled' : 'disabled'}`, to, (a) => setMailboxEnabled(getPool(), a, id, enabled))
}

export async function deleteMailboxAction(form: FormData): Promise<void> {
  const id = idOf(form)
  if (form.get('confirm') !== 'yes') redirect(`/admin/mail/${id}?confirm=delete`)
  await run('mailbox_deleted', '/admin/mail?done=deleted', `/admin/mail/${id}`, (a) => deleteMailbox(getPool(), a, id))
}

export async function requestTestAction(form: FormData): Promise<void> {
  const id = idOf(form)
  await run('mailbox_test_requested', `/admin/mail/${id}?done=queued`, `/admin/mail/${id}`, (a) => requestJob(getPool(), a, id, 'test'))
}

export async function requestRunAction(form: FormData): Promise<void> {
  const id = idOf(form)
  await run('mailbox_run_requested', `/admin/mail/${id}?done=queued`, `/admin/mail/${id}`, (a) => requestJob(getPool(), a, id, 'run'))
}

export async function addDomainAction(form: FormData): Promise<void> {
  await run('domain_added', '/admin/domains?done=added', '/admin/domains', (a) => addDomain(getPool(), a, text(form, 'domain', 300)))
}

export async function removeDomainAction(form: FormData): Promise<void> {
  const id = idOf(form)
  await run('domain_removed', '/admin/domains?done=removed', '/admin/domains', (a) => removeDomain(getPool(), a, id))
}
