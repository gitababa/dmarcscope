// The alert evaluator: for every enabled rule, work out which conditions hold
// now, open events for new ones, keep continuing ones current and resolve
// those that cleared; queue the notifications that are due.
//
// Missing data is never read as "all fine" or as "everything failed": too few
// messages give no verdict, a domain with a single DNS check has nothing to
// compare, and a DNS lookup that failed is not a record.

import { createHash } from 'node:crypto'
import type { Pool, PoolClient } from 'pg'
import { type AlertFact, clean, cleanFacts } from './render'

export type RuleKind = 'new_failing_source' | 'compliance_drop' | 'ingest_stale' | 'dns_changed'

export type RuleRow = {
  id: number
  name: string
  kind: RuleKind
  domain: string | null
  params: Record<string, unknown>
  quiet_minutes: number
  notify_resolved: boolean
}

export type Condition = { key: string; domain: string | null; summary: string; facts: AlertFact[] }

// Most conditions one rule may hold at once: a storm of new sources must not
// become a storm of notifications.
export const MAX_CONDITIONS = 50
export const MAX_REMINDERS = 3
export const RETENTION_DAYS = 180

type Q = Pick<Pool | PoolClient, 'query'>

const num = (v: unknown, d: number) => (typeof v === 'number' && Number.isFinite(v) ? v : d)

// ---------- conditions per rule kind ----------

export async function newFailingSources(db: Q, rule: RuleRow): Promise<Condition[]> {
  const min = num(rule.params.min_messages, 100)
  const days = num(rule.params.window_days, 7)
  const { rows } = await db.query(
    `SELECT d.name AS domain, host(r.source_ip) AS ip,
            SUM(r.message_count)::bigint AS total,
            SUM(r.message_count) FILTER (WHERE NOT r.dmarc_aligned)::bigint AS failing,
            MAX(m.reverse_dns) AS reverse_dns
       FROM records r
       JOIN domains d ON d.id = r.domain_id
       LEFT JOIN ip_metadata m ON m.ip = r.source_ip
      WHERE r.period_end > NOW() - make_interval(days => $1::int)
        AND ($2::text IS NULL OR d.name = $2)
      GROUP BY d.id, d.name, r.source_ip
     HAVING COALESCE(SUM(r.message_count) FILTER (WHERE NOT r.dmarc_aligned), 0) >= $3
        AND NOT EXISTS (
              SELECT 1 FROM records p
               WHERE p.domain_id = d.id AND p.source_ip = r.source_ip
                 AND p.period_end <= NOW() - make_interval(days => $1::int))
      ORDER BY failing DESC
      LIMIT ${MAX_CONDITIONS}`,
    [days, rule.domain, min]
  )
  return rows.map((r) => ({
    key: `${r.domain}|${r.ip}`,
    domain: r.domain,
    summary: `New source ${r.ip} sent ${r.failing} messages failing DMARC for ${clean(r.domain, 100)} in the last ${days} days`,
    facts: cleanFacts([
      { label: 'Source IP', value: r.ip },
      { label: 'Failing messages', value: String(r.failing) },
      { label: 'All messages', value: String(r.total) },
      ...(r.reverse_dns && r.reverse_dns !== 'unresolved' ? [{ label: 'Reverse DNS', value: r.reverse_dns }] : []),
    ]),
  }))
}

export async function complianceDrops(db: Q, rule: RuleRow): Promise<Condition[]> {
  const threshold = num(rule.params.threshold_pct, 95)
  const min = num(rule.params.min_messages, 100)
  const days = num(rule.params.window_days, 7)
  const { rows } = await db.query(
    `SELECT d.name AS domain, SUM(r.message_count)::bigint AS total,
            COALESCE(SUM(r.message_count) FILTER (WHERE r.dmarc_aligned), 0)::bigint AS passed
       FROM records r JOIN domains d ON d.id = r.domain_id
      WHERE r.period_end > NOW() - make_interval(days => $1::int) AND ($2::text IS NULL OR d.name = $2)
      GROUP BY d.id, d.name
     HAVING SUM(r.message_count) >= $3
        AND COALESCE(SUM(r.message_count) FILTER (WHERE r.dmarc_aligned), 0) * 100.0 / SUM(r.message_count) < $4
      ORDER BY d.name LIMIT ${MAX_CONDITIONS}`,
    [days, rule.domain, min, threshold]
  )
  return rows.map((r) => {
    const rate = (Number(r.passed) * 100) / Number(r.total)
    return {
      key: r.domain,
      domain: r.domain,
      summary: `DMARC compliance for ${clean(r.domain, 100)} is ${rate.toFixed(1)}%, below ${threshold}% (last ${days} days)`,
      facts: cleanFacts([
        { label: 'Compliance', value: `${rate.toFixed(1)}%` },
        { label: 'Threshold', value: `${threshold}%` },
        { label: 'Messages', value: String(r.total) },
      ]),
    }
  })
}

export async function ingestStale(db: Q, staleHours: number): Promise<Condition[]> {
  const { rows } = await db.query(
    `SELECT (SELECT started_at FROM ingest_runs ORDER BY started_at DESC LIMIT 1) AS last_started,
            (SELECT MAX(finished_at) FROM ingest_runs WHERE finished_at IS NOT NULL AND NOT failed) AS last_success,
            COALESCE((SELECT MAX(finished_at) FROM ingest_runs WHERE finished_at IS NOT NULL AND NOT failed) > NOW() - make_interval(hours => $1::int), FALSE) AS fresh`,
    [staleHours]
  )
  const r = rows[0]
  // No run recorded at all is a fresh install, not a stale one.
  if (!r || r.last_started == null || r.fresh) return []
  return [
    {
      key: 'ingest',
      domain: null,
      summary: `No ingest run has completed for ${staleHours} hours`,
      facts: cleanFacts([
        { label: 'Last successful run', value: r.last_success ? new Date(r.last_success).toISOString() : 'never' },
        { label: 'Warning after', value: `${staleHours} hours` },
      ]),
    },
  ]
}

type Published = { status?: string; record?: string | null; lookup_failed?: boolean } | undefined

const digest = (s: string | null) => createHash('sha256').update(s ?? '').digest('hex').slice(0, 12)

// Pure: compares the records published in two DNS checks (newest first).
export function recordChanges(domain: string, newer: Record<string, Published>, older: Record<string, Published>): Condition[] {
  const out: Condition[] = []
  for (const [field, label] of [['dmarc', 'DMARC'], ['spf', 'SPF']] as const) {
    const a = newer[field]
    const b = older[field]
    // A lookup that failed (or an old check that predates the marker's data
    // and has no record field at all) is not a record: nothing to compare.
    if (!a || !b || a.lookup_failed || b.lookup_failed) continue
    if (a.record === undefined || b.record === undefined) continue
    if ((a.record ?? null) === (b.record ?? null)) continue
    out.push({
      key: `${domain}|${field}|${digest(a.record ?? null)}`,
      domain,
      summary: `The published ${label} record for ${clean(domain, 100)} changed`,
      facts: cleanFacts([
        { label: 'Record', value: label },
        { label: 'Before', value: b.record ?? '(no record)' },
        { label: 'Now', value: a.record ?? '(no record)' },
      ]),
    })
  }
  return out
}

export async function dnsChanges(db: Q, rule: RuleRow): Promise<Condition[]> {
  const { rows } = await db.query(
    `SELECT name, results FROM (
       SELECT d.name, c.results, ROW_NUMBER() OVER (PARTITION BY d.id ORDER BY c.checked_at DESC, c.id DESC) AS n
         FROM dns_checks c JOIN domains d ON d.id = c.domain_id
        WHERE $1::text IS NULL OR d.name = $1) t
      WHERE n <= 2 ORDER BY name, n`,
    [rule.domain]
  )
  const byDomain = new Map<string, Array<Record<string, Published>>>()
  for (const r of rows) byDomain.set(r.name, [...(byDomain.get(r.name) ?? []), r.results])
  const out: Condition[] = []
  for (const [domain, checks] of byDomain) {
    if (checks.length < 2) continue
    out.push(...recordChanges(domain, checks[0], checks[1]))
  }
  return out.slice(0, MAX_CONDITIONS)
}

export async function conditionsFor(db: Q, rule: RuleRow, ctx: { staleHours: number }): Promise<Condition[]> {
  switch (rule.kind) {
    case 'new_failing_source':
      return newFailingSources(db, rule)
    case 'compliance_drop':
      return complianceDrops(db, rule)
    case 'ingest_stale':
      return ingestStale(db, ctx.staleHours)
    case 'dns_changed':
      return dnsChanges(db, rule)
  }
}

// ---------- lifecycle ----------

// A change of record is a one-time event: it resolves once the next check
// reads the same record as the one before it, i.e. when it is no longer among
// the conditions (the two newest checks agree).
export async function reconcile(db: PoolClient, rule: RuleRow, conditions: Condition[]): Promise<{ opened: number; resolved: number }> {
  const keys = conditions.map((c) => c.key)
  let opened = 0
  for (const c of conditions) {
    const { rows } = await db.query<{ id: string; inserted: boolean }>(
      `INSERT INTO alert_events (rule_id, dedupe_key, domain, summary, detail)
       VALUES ($1, $2, $3, $4, $5::jsonb)
       ON CONFLICT (rule_id, dedupe_key) WHERE state = 'open'
       DO UPDATE SET last_seen_at = NOW(), summary = EXCLUDED.summary, detail = EXCLUDED.detail
       RETURNING id, (xmax = 0) AS inserted`,
      [rule.id, c.key, c.domain, c.summary, JSON.stringify({ facts: c.facts })]
    )
    if (rows[0].inserted) {
      opened++
      await queueForChannels(db, rule.id, Number(rows[0].id), 'alert')
      await db.query(`UPDATE alert_events SET last_notified_at = NOW() WHERE id = $1`, [rows[0].id])
    }
  }
  const resolved = await db.query<{ id: string }>(
    `UPDATE alert_events SET state = 'resolved', resolved_at = NOW()
      WHERE rule_id = $1 AND state = 'open' AND NOT (dedupe_key = ANY($2::text[]))
      RETURNING id`,
    [rule.id, keys]
  )
  if (rule.notify_resolved) for (const r of resolved.rows) await queueForChannels(db, rule.id, Number(r.id), 'resolved')

  // Reminders: still open after the quiet period, at most MAX_REMINDERS.
  const due = await db.query<{ id: string }>(
    `UPDATE alert_events SET reminders_sent = reminders_sent + 1, last_notified_at = NOW()
      WHERE rule_id = $1 AND state = 'open' AND reminders_sent < $3
        AND last_notified_at <= NOW() - make_interval(mins => $2::int)
      RETURNING id`,
    [rule.id, rule.quiet_minutes, MAX_REMINDERS]
  )
  for (const r of due.rows) await queueForChannels(db, rule.id, Number(r.id), 'reminder')
  return { opened, resolved: resolved.rowCount ?? 0 }
}

async function queueForChannels(db: PoolClient, ruleId: number, eventId: number, kind: 'alert' | 'reminder' | 'resolved') {
  await db.query(
    `INSERT INTO alert_deliveries (event_id, channel_id, kind)
     SELECT $2, c.id, $3 FROM alert_rule_channels rc JOIN alert_channels c ON c.id = rc.channel_id
      WHERE rc.rule_id = $1 AND c.enabled`,
    [ruleId, eventId, kind]
  )
}

// ---------- one evaluation pass ----------

const LOCK_KEY = 5_000_005

export type EvaluationResult = { ran: boolean; rules: number; opened: number; resolved: number; failed: number }

// One at a time across every replica: a second caller returns at once.
export async function evaluateAll(pool: Pool, ctx: { staleHours: number }): Promise<EvaluationResult> {
  const lock = await pool.connect()
  try {
    const got = (await lock.query<{ ok: boolean }>(`SELECT pg_try_advisory_lock($1) AS ok`, [LOCK_KEY])).rows[0].ok
    if (!got) return { ran: false, rules: 0, opened: 0, resolved: 0, failed: 0 }
    try {
      await lock.query(`UPDATE alert_evaluator SET last_started_at = NOW() WHERE id = 1`)
      const rules = (
        await lock.query<RuleRow>(
          `SELECT id::int AS id, name, kind, domain, params, quiet_minutes, notify_resolved FROM alert_rules WHERE enabled ORDER BY id`
        )
      ).rows
      const result: EvaluationResult = { ran: true, rules: rules.length, opened: 0, resolved: 0, failed: 0 }
      for (const rule of rules) {
        const client = await pool.connect()
        try {
          await client.query('BEGIN')
          const conditions = await conditionsFor(client, rule, ctx)
          const r = await reconcile(client, rule, conditions)
          await client.query(`UPDATE alert_rules SET last_evaluated_at = NOW(), last_error = NULL WHERE id = $1`, [rule.id])
          await client.query('COMMIT')
          result.opened += r.opened
          result.resolved += r.resolved
        } catch (err) {
          await client.query('ROLLBACK').catch(() => {})
          result.failed++
          console.error(`[alerts] rule ${rule.id} failed:`, err instanceof Error ? err.message : String(err))
          await pool
            .query(`UPDATE alert_rules SET last_error = $2 WHERE id = $1`, [rule.id, clean(err instanceof Error ? err.message : err, 300)])
            .catch(() => {})
        } finally {
          client.release()
        }
      }
      await lock.query(
        `DELETE FROM alert_events WHERE state = 'resolved' AND resolved_at < NOW() - make_interval(days => $1::int)`,
        [RETENTION_DAYS]
      )
      await lock.query(`DELETE FROM alert_deliveries WHERE status <> 'queued' AND created_at < NOW() - make_interval(days => $1::int)`, [RETENTION_DAYS])
      await lock.query(`UPDATE alert_evaluator SET last_finished_at = NOW(), last_error = $1 WHERE id = 1`, [
        result.failed ? `${result.failed} rule(s) failed` : null,
      ])
      return result
    } finally {
      await lock.query(`SELECT pg_advisory_unlock($1)`, [LOCK_KEY]).catch(() => {})
    }
  } finally {
    lock.release()
  }
}
