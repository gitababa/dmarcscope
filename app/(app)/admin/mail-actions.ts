'use server'

// Mailbox and monitored-domain actions (administrators). Each re-checks the
// caller's role; lib/mail.ts holds the rules and writes the audit entries,
// including for refusals.

import { redirect } from 'next/navigation'
import { revalidatePath } from 'next/cache'
import { after } from 'next/server'
import { startsWorkItself, triggerIngest } from '@/lib/ingest-trigger'
import { audit, currentActor, getAccessWithRole } from '@/lib/auth/server'
import { getPool } from '@/lib/db'
import {
  type MailActor,
  type MailboxInput,
  MailRefusal,
  addDomain,
  createMailbox,
  deleteMailbox,
  failQueuedJob,
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

// A connection test takes seconds: wait for it, so the page shows the
// answer. Comfortably below the function limit of every Vercel plan.
const TEST_WAIT_MS = 60_000
// A run can take the whole pass (ingestor/oneshot.py, 240 s by default):
// keep the call open after the page has been answered, below 300 s.
const RUN_WAIT_MS = 285_000

// Without a long-running worker (Vercel), start the request now. When it
// cannot be started at all, the request records why instead of waiting.
async function startJob(jobId: number, kind: 'test' | 'run'): Promise<'done' | 'started' | 'queued'> {
  if (!startsWorkItself()) return 'queued'
  if (kind === 'test') {
    const outcome = await triggerIngest(`job:${jobId}`, { timeoutMs: TEST_WAIT_MS })
    if (!outcome.ok && !outcome.timedOut) await failQueuedJob(getPool(), jobId, `Could not start the test: ${outcome.reason}.`)
    return outcome.ok ? 'done' : 'started'
  }
  after(async () => {
    const outcome = await triggerIngest(`job:${jobId}`, { timeoutMs: RUN_WAIT_MS })
    if (!outcome.ok && !outcome.timedOut) await failQueuedJob(getPool(), jobId, `Could not start the run: ${outcome.reason}.`)
  })
  return 'started'
}

export async function requestTestAction(form: FormData): Promise<void> {
  const id = idOf(form)
  await run(
    'mailbox_test_requested',
    (state) => `/admin/mail/${id}?done=${state === 'done' ? 'tested' : state}`,
    `/admin/mail/${id}`,
    async (a) => startJob(await requestJob(getPool(), a, id, 'test'), 'test')
  )
}

export async function requestRunAction(form: FormData): Promise<void> {
  const id = idOf(form)
  await run(
    'mailbox_run_requested',
    (state) => `/admin/mail/${id}?done=${state}`,
    `/admin/mail/${id}`,
    async (a) => startJob(await requestJob(getPool(), a, id, 'run'), 'run')
  )
}

export async function addDomainAction(form: FormData): Promise<void> {
  await run('domain_added', () => `${back(form, '/admin/domains')}?done=added`, '/admin/domains', async (a) => {
    const domain = text(form, 'domain', 300)
    await addDomain(getPool(), a, domain)
    // Reports held for this domain are imported by the worker; without one,
    // ask the ingest function now.
    if (startsWorkItself()) {
      after(async () => {
        const outcome = await triggerIngest('release', { timeoutMs: RUN_WAIT_MS })
        if (!outcome.ok && !outcome.timedOut) console.error(`[domains] importing held reports could not start: ${outcome.reason}`)
      })
    }
    return domain
  })
}

export async function removeDomainAction(form: FormData): Promise<void> {
  const id = idOf(form)
  await run('domain_removed', '/admin/domains?done=removed', '/admin/domains', (a) => removeDomain(getPool(), a, id))
}
