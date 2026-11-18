'use server'

// Alert rule and channel actions (administrators). Each re-checks the
// caller's role; lib/alerts/admin.ts holds the rules and writes the audit
// entries, including for refusals.

import { redirect } from 'next/navigation'
import { revalidatePath } from 'next/cache'
import {
  type AlertActor,
  AlertRefusal,
  type ChannelInput,
  type RuleInput,
  createChannel,
  createRule,
  deleteChannel,
  deleteRule,
  requestTest,
  setRuleEnabled,
  updateChannel,
  updateRule,
} from '@/lib/alerts/admin'
import { deliverDue } from '@/lib/alerts/deliver'
import { runAlerts } from '@/lib/alerts/run'
import { audit, currentActor, getAccessWithRole } from '@/lib/auth/server'
import { getPool } from '@/lib/db'

async function admin(action: string): Promise<AlertActor> {
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

const idOf = (form: FormData, name = 'id'): number => {
  const n = Number(text(form, name, 20))
  return Number.isSafeInteger(n) && n > 0 ? n : 0
}

async function run<T>(action: string, ok: string | ((r: T) => string), fail: string, fn: (actor: AlertActor) => Promise<T>): Promise<never> {
  const actor = await admin(action)
  let result: T
  try {
    result = await fn(actor)
  } catch (err) {
    if (err instanceof AlertRefusal) {
      redirect(`${fail}${fail.includes('?') ? '&' : '?'}error=${err.code}${err.field ? `&field=${err.field}` : ''}`)
    }
    throw err
  }
  revalidatePath('/admin/alerts')
  redirect(typeof ok === 'function' ? ok(result) : ok)
}

function ruleInput(form: FormData): RuleInput {
  return {
    name: text(form, 'name', 101),
    kind: form.get('kind'),
    domain: text(form, 'domain', 300),
    minMessages: text(form, 'min_messages', 10),
    windowDays: text(form, 'window_days', 3),
    thresholdPct: text(form, 'threshold_pct', 3),
    quietMinutes: text(form, 'quiet_minutes', 6),
    notifyResolved: form.get('notify_resolved') === '1',
    enabled: form.get('enabled') === '1',
    channelIds: form.getAll('channels').map((v) => Number(v)).filter((n) => Number.isSafeInteger(n) && n > 0),
  }
}

function channelInput(form: FormData): ChannelInput {
  return {
    name: text(form, 'name', 101),
    kind: form.get('kind'),
    recipients: text(form, 'recipients', 2000),
    url: text(form, 'url', 2001),
    signingSecret: text(form, 'signing_secret', 300),
    enabled: form.get('enabled') === '1',
  }
}

export async function createRuleAction(form: FormData): Promise<void> {
  await run('alert_rule_created', '/admin/alerts?done=rule_created', '/admin/alerts?new=rule', (a) => createRule(getPool(), a, ruleInput(form)))
}

export async function updateRuleAction(form: FormData): Promise<void> {
  const id = idOf(form)
  await run('alert_rule_updated', '/admin/alerts?done=rule_saved', `/admin/alerts?rule=${id}`, (a) => updateRule(getPool(), a, id, ruleInput(form)))
}

export async function toggleRuleAction(form: FormData): Promise<void> {
  const id = idOf(form)
  const enabled = form.get('enabled') === '1'
  await run('alert_rule_enabled', `/admin/alerts?done=${enabled ? 'rule_enabled' : 'rule_disabled'}`, '/admin/alerts', (a) => setRuleEnabled(getPool(), a, id, enabled))
}

export async function deleteRuleAction(form: FormData): Promise<void> {
  const id = idOf(form)
  if (form.get('confirm') !== 'yes') redirect(`/admin/alerts?rule=${id}&confirm=delete`)
  await run('alert_rule_deleted', '/admin/alerts?done=rule_deleted', `/admin/alerts?rule=${id}`, (a) => deleteRule(getPool(), a, id))
}

export async function createChannelAction(form: FormData): Promise<void> {
  const kind = String(form.get('kind') ?? 'email').replace(/[^a-z]/g, '').slice(0, 20)
  await run('alert_channel_created', '/admin/alerts?done=channel_created', `/admin/alerts?newchannel=${kind}`, (a) => createChannel(getPool(), a, channelInput(form)))
}

export async function updateChannelAction(form: FormData): Promise<void> {
  const id = idOf(form)
  await run('alert_channel_updated', '/admin/alerts?done=channel_saved', `/admin/alerts?channel=${id}`, (a) => updateChannel(getPool(), a, id, channelInput(form)))
}

export async function deleteChannelAction(form: FormData): Promise<void> {
  const id = idOf(form)
  if (form.get('confirm') !== 'yes') redirect(`/admin/alerts?channel=${id}&confirm=delete`)
  await run('alert_channel_deleted', '/admin/alerts?done=channel_deleted', `/admin/alerts?channel=${id}`, (a) => deleteChannel(getPool(), a, id))
}

// Queues a test and sends it straight away; the result is in the history.
export async function testChannelAction(form: FormData): Promise<void> {
  const id = idOf(form)
  await run('alert_channel_test', '/admin/alerts?done=tested#history-head', '/admin/alerts', async (a) => {
    await requestTest(getPool(), a, id)
    await deliverDue(getPool())
  })
}

// Evaluate now instead of waiting for the next tick.
export async function evaluateNowAction(): Promise<void> {
  await admin('alert_evaluate_now')
  await runAlerts(getPool())
  revalidatePath('/admin/alerts')
  redirect('/admin/alerts?done=evaluated')
}
