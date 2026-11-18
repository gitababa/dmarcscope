// What the timer and /api/cron/alerts run: evaluate every rule, then send
// what is due. With no enabled rule and nothing queued it makes no outbound
// connection at all.

import type { Pool } from 'pg'
import { machineScope } from '../auth/access'
import { getPool } from '../db'
import { runAndStoreDnsCheck } from '../dns-run'
import { getIngestStaleHours } from '../settings'
import { deliverDue } from './deliver'
import { type EvaluationResult, evaluateAll } from './evaluate'

export async function runAlerts(pool: Pool = getPool()): Promise<EvaluationResult & { sent: number; failed: number; retried: number }> {
  const evaluation = await evaluateAll(pool, { staleHours: await getIngestStaleHours() })
  const delivery = await deliverDue(pool)
  return { ...evaluation, ...delivery }
}

const DNS_LOCK_KEY = 5_000_006
const DNS_REFRESH_AFTER_HOURS = 23

// A "record changed" rule compares DNS checks, and a self-hosted install with
// no scheduler never makes them: while such a rule is enabled, a long-running
// web app refreshes the domains whose latest check is a day old. One replica
// at a time, a few domains at once, within a time budget.
export async function refreshDnsChecks(pool: Pool = getPool()): Promise<number> {
  const lock = await pool.connect()
  try {
    if (!(await lock.query<{ ok: boolean }>(`SELECT pg_try_advisory_lock($1) AS ok`, [DNS_LOCK_KEY])).rows[0].ok) return 0
    try {
      const wanted = await lock.query(`SELECT 1 FROM alert_rules WHERE enabled AND kind = 'dns_changed' LIMIT 1`)
      if (!wanted.rowCount) return 0
      const { rows } = await lock.query<{ name: string }>(
        `SELECT d.name FROM domains d
          WHERE NOT EXISTS (SELECT 1 FROM dns_checks c WHERE c.domain_id = d.id AND c.checked_at > NOW() - make_interval(hours => $1::int))
          ORDER BY d.name LIMIT 200`,
        [DNS_REFRESH_AFTER_HOURS]
      )
      const queue = rows.map((r) => r.name)
      const deadline = Date.now() + 240_000
      let done = 0
      await Promise.all(
        Array.from({ length: Math.min(4, queue.length) }, async () => {
          for (let d = queue.shift(); d && Date.now() < deadline; d = queue.shift()) {
            try {
              await runAndStoreDnsCheck(machineScope(), d, { force: true })
              done++
            } catch (e) {
              console.error(`[alerts] DNS check for ${d} failed:`, e instanceof Error ? e.message : String(e))
            }
          }
        })
      )
      return done
    } finally {
      await lock.query(`SELECT pg_advisory_unlock($1)`, [DNS_LOCK_KEY]).catch(() => {})
    }
  } finally {
    lock.release()
  }
}

export const EVALUATION_INTERVAL_MS = 5 * 60_000

let timer: ReturnType<typeof setInterval> | null = null

// Long-running processes only. Serverless deployments use /api/cron/alerts.
export function startAlertTimer(): void {
  if (timer || process.env.VERCEL) return
  let busy = false
  const tick = () => {
    if (busy) return
    busy = true
    refreshDnsChecks()
      .then(() => runAlerts())
      .catch((err) => console.error('[alerts] evaluation failed:', err instanceof Error ? err.message : String(err)))
      .finally(() => {
        busy = false
      })
  }
  timer = setInterval(tick, EVALUATION_INTERVAL_MS)
  timer.unref()
}
