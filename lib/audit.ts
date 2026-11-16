// Audit trail: every sign-in, refusal, setting change, user change and setup
// step. Each entry goes to the audit_log table (append-only) and, as in 1.1.0,
// to stdout as one JSON line with "type":"audit" for the platform's log
// pipeline.
//
// `detail` must never carry a secret value: callers record that a secret
// changed, never what it is. Values are untrusted where they come from a
// request (an email typed into a form), so they are length-limited here.

import type { Pool, PoolClient } from 'pg'

export type Actor = { userId: number | null; email: string | null; ip: string | null }

export const SYSTEM_ACTOR: Actor = { userId: null, email: null, ip: null }

export type AuditEntry = {
  action: string
  actor?: Actor
  target?: string | null
  detail?: Record<string, unknown>
}

type Queryable = Pick<Pool | PoolClient, 'query'>

const clip = (v: string | null | undefined, n: number) => (v == null ? null : v.length > n ? `${v.slice(0, n)}…` : v)

function stdoutLine(entry: AuditEntry): void {
  const actor = entry.actor ?? SYSTEM_ACTOR
  console.log(
    JSON.stringify({
      level: 'info',
      type: 'audit',
      event: entry.action,
      time: new Date().toISOString(),
      ...(actor.email ? { email: actor.email } : {}),
      ...(actor.userId != null ? { user_id: actor.userId } : {}),
      ...(actor.ip ? { ip: actor.ip } : {}),
      ...(entry.target ? { target: entry.target } : {}),
      ...(entry.detail ?? {}),
    })
  )
}

// Inside a transaction: pass the transaction's client so the entry commits or
// rolls back with the change it describes. The stdout line is written only
// after the insert succeeded.
export async function writeAudit(db: Queryable, entry: AuditEntry): Promise<void> {
  const actor = entry.actor ?? SYSTEM_ACTOR
  await db.query(
    `INSERT INTO audit_log (actor_user_id, actor_email, action, target, detail, ip) VALUES ($1, $2, $3, $4, $5, $6)`,
    [
      actor.userId,
      clip(actor.email, 320),
      entry.action,
      clip(entry.target ?? null, 500),
      JSON.stringify(entry.detail ?? {}),
      clip(actor.ip, 64),
    ]
  )
  stdoutLine(entry)
}

// Outside a transaction, for events that must not fail the request they
// describe (a refused sign-in is still refused when the database insert
// fails): the stdout line is always written.
export async function recordAudit(db: Queryable, entry: AuditEntry): Promise<void> {
  try {
    await writeAudit(db, entry)
  } catch (err) {
    stdoutLine(entry)
    console.error('[audit] could not write to audit_log:', err instanceof Error ? err.message : String(err))
  }
}
