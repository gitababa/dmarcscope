// Alert rules and channels managed in the panel (administrators and owners).
// Every change is one transaction that re-reads the caller's role and writes
// the audit entry; refusals are audited too. A channel secret (webhook URL,
// signing secret) is encrypted here and never read back for display: the
// forms show "set" and the host only.

import type { Pool, PoolClient } from 'pg'
import { type Actor, recordAudit, writeAudit } from '../audit'
import { atLeast } from '../auth/roles'
import type { Role } from '../auth/types'
import type { Env } from '../config'
import { encryptSecret } from '../crypto'
import { normalizeDomain } from '../mail'
import { channelContext } from './deliver'
import type { RuleKind } from './evaluate'
import { isAddress } from './smtp'

export type AlertActor = Actor & { role: Role }
export type ChannelKind = 'email' | 'webhook' | 'slack'

export type AlertRefusalCode = 'not_allowed' | 'invalid' | 'not_found' | 'rate_limited'

export class AlertRefusal extends Error {
  constructor(
    public code: AlertRefusalCode,
    public field?: string
  ) {
    super(field ? `${code}:${field}` : code)
    this.name = 'AlertRefusal'
  }
}

export const RULE_KINDS: Record<RuleKind, { label: string; help: string }> = {
  new_failing_source: { label: 'New source failing DMARC', help: 'A sending IP that is new for the domain and fails DMARC above a message threshold.' },
  compliance_drop: { label: 'Compliance below a threshold', help: 'The DMARC pass rate for a domain falls below a percentage.' },
  ingest_stale: { label: 'Ingest stale', help: 'No ingest run has completed within the staleness window (Settings: Ingest staleness warning).' },
  dns_changed: { label: 'DMARC or SPF record changed', help: 'The published record differs between the latest two DNS checks.' },
}

export const CHANNEL_KINDS: Record<ChannelKind, { label: string }> = {
  email: { label: 'Email (through the SMTP server in Settings)' },
  webhook: { label: 'Signed webhook' },
  slack: { label: 'Slack-compatible webhook' },
}

const isRuleKind = (v: unknown): v is RuleKind => typeof v === 'string' && Object.prototype.hasOwnProperty.call(RULE_KINDS, v)
const isChannelKind = (v: unknown): v is ChannelKind => typeof v === 'string' && Object.prototype.hasOwnProperty.call(CHANNEL_KINDS, v)

// ---------- validation ----------

const intIn = (raw: string, min: number, max: number, field: string, fallback?: number): number => {
  const t = raw.trim()
  if (t === '' && fallback != null) return fallback
  if (!/^\d{1,9}$/.test(t) || Number(t) < min || Number(t) > max) throw new AlertRefusal('invalid', field)
  return Number(t)
}

const name = (raw: string): string => {
  const s = raw.trim()
  if (!s || s.length > 100 || /[\x00-\x1f\x7f]/.test(s)) throw new AlertRefusal('invalid', 'name')
  return s
}

export type RuleInput = {
  name: string
  kind: unknown
  domain: string
  minMessages: string
  windowDays: string
  thresholdPct: string
  quietMinutes: string
  notifyResolved: boolean
  enabled: boolean
  channelIds: number[]
}

export type ValidRule = {
  name: string
  kind: RuleKind
  domain: string | null
  params: Record<string, number>
  quietMinutes: number
  notifyResolved: boolean
  enabled: boolean
  channelIds: number[]
}

export function validateRule(i: RuleInput): ValidRule {
  if (!isRuleKind(i.kind)) throw new AlertRefusal('invalid', 'kind')
  const domain = i.domain.trim() ? normalizeDomain(i.domain) : null
  if (i.domain.trim() && !domain) throw new AlertRefusal('invalid', 'domain')
  const params: Record<string, number> = {}
  if (i.kind === 'new_failing_source' || i.kind === 'compliance_drop') {
    params.min_messages = intIn(i.minMessages, 1, 10_000_000, 'min_messages', 100)
    params.window_days = intIn(i.windowDays, 1, 30, 'window_days', 7)
  }
  if (i.kind === 'compliance_drop') params.threshold_pct = intIn(i.thresholdPct, 1, 100, 'threshold_pct', 95)
  if (i.kind === 'ingest_stale' && domain) throw new AlertRefusal('invalid', 'domain')
  return {
    name: name(i.name),
    kind: i.kind,
    domain,
    params,
    quietMinutes: intIn(i.quietMinutes, 60, 10080, 'quiet_minutes', 1440),
    notifyResolved: i.notifyResolved,
    enabled: i.enabled,
    channelIds: [...new Set(i.channelIds)].slice(0, 50),
  }
}

export type ChannelInput = {
  name: string
  kind: unknown
  recipients: string // email: addresses separated by commas or line breaks
  url: string // webhook, slack: '' keeps the saved one
  signingSecret: string // webhook: required with a new URL
  enabled: boolean
}

export type ValidChannel = { name: string; kind: ChannelKind; recipients: string[]; enabled: boolean }

export function validateChannel(i: ChannelInput): ValidChannel {
  if (!isChannelKind(i.kind)) throw new AlertRefusal('invalid', 'kind')
  let recipients: string[] = []
  if (i.kind === 'email') {
    recipients = [...new Set(i.recipients.split(/[\s,;]+/).map((a) => a.trim()).filter(Boolean))]
    if (recipients.length === 0 || recipients.length > 10 || !recipients.every(isAddress)) throw new AlertRefusal('invalid', 'recipients')
  }
  return { name: name(i.name), kind: i.kind, recipients, enabled: i.enabled }
}

function checkUrl(raw: string): URL {
  let u: URL
  try {
    u = new URL(raw.trim())
  } catch {
    throw new AlertRefusal('invalid', 'url')
  }
  // The destination rules (https, private addresses) are applied on every
  // delivery; here only a URL that can never work is refused.
  if ((u.protocol !== 'https:' && u.protocol !== 'http:') || u.username || u.password || raw.length > 2000) throw new AlertRefusal('invalid', 'url')
  return u
}

function checkSigningSecret(raw: string): string {
  if (raw.length < 16 || raw.length > 256 || /[\s\x00-\x1f\x7f]/.test(raw)) throw new AlertRefusal('invalid', 'signing_secret')
  return raw
}

// ---------- changes ----------

async function guarded<T>(
  db: Pool,
  actor: AlertActor,
  action: string,
  target: string,
  fn: (c: PoolClient) => Promise<{ result: T; detail: Record<string, unknown>; target?: string }>
): Promise<T> {
  try {
    if (!atLeast(actor.role, 'admin')) throw new AlertRefusal('not_allowed')
    const client = await db.connect()
    try {
      await client.query('BEGIN')
      if (actor.userId != null) {
        // The caller as the database sees them now, not as their session said.
        const me = await client.query<{ status: string; role: Role }>(`SELECT status, role FROM users WHERE id = $1`, [actor.userId])
        if (me.rows[0]?.status !== 'active' || !atLeast(me.rows[0].role, 'admin')) throw new AlertRefusal('not_allowed')
      }
      const out = await fn(client)
      await writeAudit(client, { action, actor, target: out.target ?? target, detail: out.detail })
      await client.query('COMMIT')
      return out.result
    } catch (err) {
      await client.query('ROLLBACK').catch(() => {})
      throw err
    } finally {
      client.release()
    }
  } catch (err) {
    if (err instanceof AlertRefusal) {
      await recordAudit(db, { action: 'action_refused', actor, target, detail: { action, reason: err.code, ...(err.field ? { field: err.field } : {}) } })
    }
    throw err
  }
}

async function setRuleChannels(c: PoolClient, ruleId: number, channelIds: number[]) {
  await c.query(`DELETE FROM alert_rule_channels WHERE rule_id = $1`, [ruleId])
  if (channelIds.length) {
    const { rows } = await c.query<{ id: string }>(`SELECT id FROM alert_channels WHERE id = ANY($1::bigint[])`, [channelIds])
    if (rows.length !== channelIds.length) throw new AlertRefusal('invalid', 'channels')
    await c.query(`INSERT INTO alert_rule_channels (rule_id, channel_id) SELECT $1, UNNEST($2::bigint[])`, [ruleId, channelIds])
  }
}

const ruleDetail = (v: ValidRule) => ({
  name: v.name, kind: v.kind, domain: v.domain, params: v.params, quiet_minutes: v.quietMinutes, notify_resolved: v.notifyResolved, enabled: v.enabled, channels: v.channelIds,
})

export async function createRule(db: Pool, actor: AlertActor, input: RuleInput): Promise<number> {
  return guarded(db, actor, 'alert_rule_created', 'alert_rule', async (c) => {
    const v = validateRule(input)
    const { rows } = await c.query<{ id: string }>(
      `INSERT INTO alert_rules (name, kind, enabled, domain, params, quiet_minutes, notify_resolved, created_by, updated_by)
       VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7, $8, $8) RETURNING id`,
      [v.name, v.kind, v.enabled, v.domain, JSON.stringify(v.params), v.quietMinutes, v.notifyResolved, actor.userId]
    )
    const id = Number(rows[0].id)
    await setRuleChannels(c, id, v.channelIds)
    return { result: id, detail: ruleDetail(v), target: `alert_rule:${id}` }
  })
}

export async function updateRule(db: Pool, actor: AlertActor, id: number, input: RuleInput): Promise<void> {
  await guarded(db, actor, 'alert_rule_updated', `alert_rule:${id}`, async (c) => {
    const v = validateRule(input)
    const { rowCount } = await c.query(
      `UPDATE alert_rules SET name = $2, kind = $3, enabled = $4, domain = $5, params = $6::jsonb, quiet_minutes = $7, notify_resolved = $8,
         updated_at = NOW(), updated_by = $9 WHERE id = $1`,
      [id, v.name, v.kind, v.enabled, v.domain, JSON.stringify(v.params), v.quietMinutes, v.notifyResolved, actor.userId]
    )
    if (!rowCount) throw new AlertRefusal('not_found')
    await setRuleChannels(c, id, v.channelIds)
    return { result: undefined, detail: ruleDetail(v) }
  })
}

export async function setRuleEnabled(db: Pool, actor: AlertActor, id: number, enabled: boolean): Promise<void> {
  await guarded(db, actor, enabled ? 'alert_rule_enabled' : 'alert_rule_disabled', `alert_rule:${id}`, async (c) => {
    const { rowCount } = await c.query(`UPDATE alert_rules SET enabled = $2, updated_at = NOW(), updated_by = $3 WHERE id = $1`, [id, enabled, actor.userId])
    if (!rowCount) throw new AlertRefusal('not_found')
    return { result: undefined, detail: {} }
  })
}

export async function deleteRule(db: Pool, actor: AlertActor, id: number): Promise<void> {
  await guarded(db, actor, 'alert_rule_deleted', `alert_rule:${id}`, async (c) => {
    const { rows } = await c.query<{ name: string }>(`DELETE FROM alert_rules WHERE id = $1 RETURNING name`, [id])
    if (!rows[0]) throw new AlertRefusal('not_found')
    return { result: undefined, detail: { name: rows[0].name } }
  })
}

function secretFor(kind: ChannelKind, id: number, input: ChannelInput, env: Env): { envelope: string; host: string } {
  const u = checkUrl(input.url)
  const stored = kind === 'webhook' ? { url: input.url.trim(), signing_secret: checkSigningSecret(input.signingSecret) } : { url: input.url.trim() }
  return { envelope: encryptSecret('alert', channelContext(id), JSON.stringify(stored), env), host: u.host }
}

export async function createChannel(db: Pool, actor: AlertActor, input: ChannelInput, env: Env = process.env): Promise<number> {
  return guarded(db, actor, 'alert_channel_created', 'alert_channel', async (c) => {
    const v = validateChannel(input)
    if (v.kind !== 'email' && !input.url.trim()) throw new AlertRefusal('invalid', 'url')
    const { rows } = await c.query<{ id: string }>(
      `INSERT INTO alert_channels (name, kind, enabled, config, created_by, updated_by) VALUES ($1, $2, $3, '{}'::jsonb, $4, $4) RETURNING id`,
      [v.name, v.kind, v.enabled, actor.userId]
    )
    const id = Number(rows[0].id)
    let host: string | null = null
    if (v.kind === 'email') {
      await c.query(`UPDATE alert_channels SET config = $2::jsonb WHERE id = $1`, [id, JSON.stringify({ recipients: v.recipients })])
    } else {
      const s = secretFor(v.kind, id, input, env)
      host = s.host
      await c.query(`UPDATE alert_channels SET secret = $2, secret_updated_at = NOW(), config = $3::jsonb WHERE id = $1`, [id, s.envelope, JSON.stringify({ host })])
    }
    return { result: id, detail: { name: v.name, kind: v.kind, enabled: v.enabled, ...(v.kind === 'email' ? { recipients: v.recipients } : { host, secret: 'set' }) }, target: `alert_channel:${id}` }
  })
}

// The kind of a channel never changes (create another). A webhook or Slack
// address is replaced as a whole: the new address (and, for a webhook, the
// signing secret) must be typed, so a saved URL can never be re-pointed while
// keeping the secret that came with another one.
export async function updateChannel(db: Pool, actor: AlertActor, id: number, input: ChannelInput, env: Env = process.env): Promise<void> {
  await guarded(db, actor, 'alert_channel_updated', `alert_channel:${id}`, async (c) => {
    const existing = (await c.query<{ kind: ChannelKind }>(`SELECT kind FROM alert_channels WHERE id = $1 FOR UPDATE`, [id])).rows[0]
    if (!existing) throw new AlertRefusal('not_found')
    const v = validateChannel({ ...input, kind: existing.kind })
    await c.query(`UPDATE alert_channels SET name = $2, enabled = $3, updated_at = NOW(), updated_by = $4 WHERE id = $1`, [id, v.name, v.enabled, actor.userId])
    let secret: 'kept' | 'replaced' | undefined
    let host: string | undefined
    if (v.kind === 'email') {
      await c.query(`UPDATE alert_channels SET config = $2::jsonb WHERE id = $1`, [id, JSON.stringify({ recipients: v.recipients })])
    } else if (input.url.trim() || input.signingSecret) {
      const s = secretFor(v.kind, id, input, env)
      host = s.host
      secret = 'replaced'
      await c.query(`UPDATE alert_channels SET secret = $2, secret_updated_at = NOW(), config = $3::jsonb WHERE id = $1`, [id, s.envelope, JSON.stringify({ host })])
    } else {
      secret = 'kept'
    }
    return { result: undefined, detail: { name: v.name, enabled: v.enabled, ...(v.kind === 'email' ? { recipients: v.recipients } : { secret, ...(host ? { host } : {}) }) } }
  })
}

export async function deleteChannel(db: Pool, actor: AlertActor, id: number): Promise<void> {
  await guarded(db, actor, 'alert_channel_deleted', `alert_channel:${id}`, async (c) => {
    const { rows } = await c.query<{ name: string }>(`DELETE FROM alert_channels WHERE id = $1 RETURNING name`, [id])
    if (!rows[0]) throw new AlertRefusal('not_found')
    return { result: undefined, detail: { name: rows[0].name } }
  })
}

// Queues one test delivery; the caller sends it straight away. One per
// channel every ten seconds.
export async function requestTest(db: Pool, actor: AlertActor, id: number): Promise<void> {
  await guarded(db, actor, 'alert_channel_test', `alert_channel:${id}`, async (c) => {
    const ch = (await c.query(`SELECT id FROM alert_channels WHERE id = $1 FOR UPDATE`, [id])).rows[0]
    if (!ch) throw new AlertRefusal('not_found')
    const recent = await c.query(
      `SELECT 1 FROM alert_deliveries WHERE channel_id = $1 AND kind = 'test' AND created_at > NOW() - INTERVAL '10 seconds'`,
      [id]
    )
    if (recent.rowCount) throw new AlertRefusal('rate_limited')
    await c.query(`INSERT INTO alert_deliveries (channel_id, kind, requested_by) VALUES ($1, 'test', $2)`, [id, actor.userId])
    return { result: undefined, detail: {} }
  })
}

// ---------- reading ----------

type Q = Pick<Pool, 'query'>

export type ChannelRow = {
  id: number; name: string; kind: ChannelKind; enabled: boolean; recipients: string[]; host: string | null; secret_set: boolean; secret_updated_at: string | null
  last_delivery: { status: string; kind: string; error: string | null; created_at: string } | null
}
export type RuleListRow = {
  id: number; name: string; kind: RuleKind; enabled: boolean; domain: string | null; params: Record<string, number>; quiet_minutes: number; notify_resolved: boolean
  last_evaluated_at: string | null; last_error: string | null; open_events: number; channel_ids: number[]
}
export type EventRow = { id: number; rule_name: string; domain: string | null; state: string; summary: string; first_seen_at: string; last_seen_at: string; resolved_at: string | null }
export type DeliveryRow = { id: number; channel_name: string; kind: string; status: string; attempts: number; error: string | null; created_at: string; finished_at: string | null; event_id: number | null }

export async function listChannels(db: Q): Promise<ChannelRow[]> {
  const { rows } = await db.query(
    `SELECT c.id::int AS id, c.name, c.kind, c.enabled, COALESCE(c.config->'recipients', '[]'::jsonb) AS recipients, c.config->>'host' AS host,
            c.secret IS NOT NULL AS secret_set, c.secret_updated_at,
            (SELECT row_to_json(d) FROM (SELECT status, kind, error, created_at FROM alert_deliveries WHERE channel_id = c.id ORDER BY id DESC LIMIT 1) d) AS last_delivery
       FROM alert_channels c ORDER BY c.name, c.id`
  )
  return rows
}

export async function listRules(db: Q): Promise<RuleListRow[]> {
  const { rows } = await db.query(
    `SELECT r.id::int AS id, r.name, r.kind, r.enabled, r.domain, r.params, r.quiet_minutes, r.notify_resolved, r.last_evaluated_at, r.last_error,
            (SELECT COUNT(*)::int FROM alert_events e WHERE e.rule_id = r.id AND e.state = 'open') AS open_events,
            COALESCE((SELECT array_agg(rc.channel_id::int ORDER BY rc.channel_id) FROM alert_rule_channels rc WHERE rc.rule_id = r.id), '{}') AS channel_ids
       FROM alert_rules r ORDER BY r.name, r.id`
  )
  return rows
}

export async function listEvents(db: Q, limit = 50): Promise<EventRow[]> {
  const { rows } = await db.query(
    `SELECT e.id::int AS id, r.name AS rule_name, e.domain, e.state, e.summary, e.first_seen_at, e.last_seen_at, e.resolved_at
       FROM alert_events e JOIN alert_rules r ON r.id = e.rule_id ORDER BY (e.state = 'open') DESC, e.first_seen_at DESC LIMIT $1`,
    [limit]
  )
  return rows
}

export async function listDeliveries(db: Q, limit = 50): Promise<DeliveryRow[]> {
  const { rows } = await db.query(
    `SELECT d.id::int AS id, c.name AS channel_name, d.kind, d.status, d.attempts, d.error, d.created_at, d.finished_at, d.event_id::int AS event_id
       FROM alert_deliveries d JOIN alert_channels c ON c.id = d.channel_id ORDER BY d.id DESC LIMIT $1`,
    [limit]
  )
  return rows
}

export async function evaluatorState(db: Q): Promise<{ last_started_at: string | null; last_finished_at: string | null; last_error: string | null }> {
  const { rows } = await db.query(`SELECT last_started_at, last_finished_at, last_error FROM alert_evaluator WHERE id = 1`)
  return rows[0] ?? { last_started_at: null, last_finished_at: null, last_error: null }
}
