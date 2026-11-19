// Reports mailboxes and monitored domains configured in the panel
// (milestone 4). Administrators manage them; the worker (python -m ingestor
// serve) reads the mailboxes.
//
// Credentials are never readable through the web app: a mailbox secret is
// encrypted here (purpose 'mailbox', bound to its row) and only the worker
// decrypts it. Nothing in the web app can decrypt that purpose
// (lib/crypto.ts refuses it, and tests/unit/mail-secrets.test.ts checks the
// sources). Forms show whether a secret is set and accept a replacement.
//
// "Test connection" and "Run now" are jobs for the worker (worker_jobs): the
// web app never opens a mailbox itself. On Vercel, with no long-running
// worker, the web app starts a one-off pass for the job at once
// (lib/ingest-trigger.ts); elsewhere the worker picks it up.

import type { Pool, PoolClient } from 'pg'
import { type Actor, recordAudit, writeAudit } from './audit'
import { atLeast } from './auth/roles'
import type { Role } from './auth/types'
import { type Env, envList } from './config'
import { encryptMailboxSecret } from './crypto'

export type MailActor = Actor & { role: Role }

export type MailboxKind = 'imap' | 'microsoft' | 'google'

export const KINDS: Record<MailboxKind, { label: string; host: string | null; secretLabel: string; verified: boolean }> = {
  imap: { label: 'IMAP with a password', host: null, secretLabel: 'Password', verified: true },
  microsoft: { label: 'Microsoft 365 (app registration)', host: 'outlook.office365.com', secretLabel: 'Client secret', verified: false },
  google: { label: 'Google Workspace (service account)', host: 'imap.gmail.com', secretLabel: 'Service-account key (JSON)', verified: false },
}

export function isKind(v: unknown): v is MailboxKind {
  return typeof v === 'string' && Object.prototype.hasOwnProperty.call(KINDS, v)
}

export type MailRefusalCode = 'not_allowed' | 'invalid' | 'not_found' | 'environment' | 'duplicate'

export class MailRefusal extends Error {
  constructor(
    public code: MailRefusalCode,
    public field?: string
  ) {
    super(field ? `${code}:${field}` : code)
    this.name = 'MailRefusal'
  }
}

// ---------- reading ----------

export type MailboxRow = {
  id: number
  name: string
  kind: MailboxKind
  enabled: boolean
  host: string
  port: number
  security: 'ssl' | 'starttls'
  username: string
  tenant_id: string | null
  client_id: string | null
  secret_set: boolean
  secret_updated_at: string | null
  folder: string
  processed_folder: string | null
  invalid_folder: string
  interval_minutes: number
  updated_at: string
  last_run: RunRow | null
  next_run_at: string | null
}

export type RunRow = {
  id: number
  started_at: string
  finished_at: string | null
  failed: boolean
  trigger: string
  messages_fetched: number
  reports_parsed: number
  reports_skipped: number
  errors: Array<{ error?: string; message?: string; uid?: string; subject?: string; file?: string }> | null
}

export type JobRow = {
  id: number
  kind: 'test' | 'run'
  status: 'queued' | 'running' | 'done' | 'failed'
  requested_at: string
  finished_at: string | null
  requested_by_email: string | null
  result: { ok?: boolean; message?: string } | null
}

type Q = Pick<Pool | PoolClient, 'query'>

// The secret column itself is never selected: only whether it is set.
const MAILBOX_COLUMNS = `m.id::int AS id, m.name, m.kind, m.enabled, m.host, m.port, m.security, m.username, m.tenant_id, m.client_id,
  (m.secret IS NOT NULL) AS secret_set, m.secret_updated_at, m.folder, m.processed_folder, m.invalid_folder,
  m.interval_minutes, m.updated_at`

const RUN_COLUMNS = `id::int AS id, started_at, finished_at, failed, trigger, messages_fetched, reports_parsed, reports_skipped, errors`

export async function listMailboxes(db: Q): Promise<MailboxRow[]> {
  const { rows } = await db.query(
    `SELECT ${MAILBOX_COLUMNS},
       (SELECT row_to_json(r) FROM (SELECT ${RUN_COLUMNS} FROM ingest_runs WHERE mailbox_id = m.id ORDER BY started_at DESC LIMIT 1) r) AS last_run,
       CASE WHEN m.enabled THEN COALESCE(
         (SELECT MAX(started_at) FROM ingest_runs WHERE mailbox_id = m.id) + make_interval(mins => m.interval_minutes), NOW())
       END AS next_run_at
     FROM mailboxes m ORDER BY m.name, m.id`
  )
  return rows
}

export async function getMailbox(db: Q, id: number): Promise<MailboxRow | null> {
  const all = await db.query(
    `SELECT ${MAILBOX_COLUMNS},
       (SELECT row_to_json(r) FROM (SELECT ${RUN_COLUMNS} FROM ingest_runs WHERE mailbox_id = m.id ORDER BY started_at DESC LIMIT 1) r) AS last_run,
       CASE WHEN m.enabled THEN COALESCE(
         (SELECT MAX(started_at) FROM ingest_runs WHERE mailbox_id = m.id) + make_interval(mins => m.interval_minutes), NOW())
       END AS next_run_at
     FROM mailboxes m WHERE m.id = $1`,
    [id]
  )
  return all.rows[0] ?? null
}

export async function listRuns(db: Q, mailboxId: number, limit = 50): Promise<RunRow[]> {
  const { rows } = await db.query(`SELECT ${RUN_COLUMNS} FROM ingest_runs WHERE mailbox_id = $1 ORDER BY started_at DESC LIMIT $2`, [
    mailboxId,
    Math.min(200, Math.max(1, limit)),
  ])
  return rows
}

export async function listJobs(db: Q, mailboxId: number, limit = 10): Promise<JobRow[]> {
  const { rows } = await db.query(
    `SELECT j.id::int AS id, j.kind, j.status, j.requested_at, j.finished_at, u.email AS requested_by_email, j.result
     FROM worker_jobs j LEFT JOIN users u ON u.id = j.requested_by
     WHERE j.mailbox_id = $1 ORDER BY j.requested_at DESC, j.id DESC LIMIT $2`,
    [mailboxId, limit]
  )
  return rows
}

export const WORKER_ALIVE_SECONDS = 120

export type WorkerStatus = { alive: number; lastSeen: string | null; versions: string[] }

export async function workerStatus(db: Q): Promise<WorkerStatus> {
  const { rows } = await db.query<{ alive: number; last_seen: string | null; versions: string[] | null }>(
    `SELECT COUNT(*) FILTER (WHERE seen_at > NOW() - make_interval(secs => $1))::int AS alive,
            MAX(seen_at) AS last_seen,
            ARRAY_AGG(DISTINCT version) FILTER (WHERE seen_at > NOW() - make_interval(secs => $1) AND version IS NOT NULL) AS versions
     FROM worker_heartbeats WHERE mode = 'serve'`,
    [WORKER_ALIVE_SECONDS]
  )
  return { alive: rows[0]?.alive ?? 0, lastSeen: rows[0]?.last_seen ?? null, versions: rows[0]?.versions ?? [] }
}

// When the work could not even be started (lib/ingest-trigger.ts), the
// request says why, instead of waiting for a worker that never comes.
export async function failQueuedJob(db: Q, jobId: number, message: string): Promise<void> {
  await db.query(
    `UPDATE worker_jobs SET status = 'failed', finished_at = NOW(), result = $2::jsonb WHERE id = $1 AND status = 'queued'`,
    [jobId, JSON.stringify({ ok: false, message: message.slice(0, 500) })]
  )
}

// How often scheduled passes (ingestor/oneshot.py) actually happen: the last
// one, and the typical gap between the recent ones. The app cannot ask
// Vercel which plan or schedule a project has, so it reports what it sees.
export type PassStatus = { lastAt: string | null; typicalGapMinutes: number | null; count: number }

export async function passStatus(db: Q): Promise<PassStatus> {
  const { rows } = await db.query<{ started_at: string }>(
    `SELECT started_at FROM ingest_passes WHERE trigger = 'schedule' ORDER BY started_at DESC LIMIT 9`
  )
  const times = rows.map((r) => new Date(r.started_at).getTime())
  const gaps = times.slice(1).map((t, i) => (times[i] - t) / 60_000).sort((a, b) => a - b)
  return {
    lastAt: rows[0]?.started_at ?? null,
    typicalGapMinutes: gaps.length ? Math.round(gaps[Math.floor(gaps.length / 2)]) : null,
    count: rows.length,
  }
}

// ---------- validation ----------

export type MailboxInput = {
  name: string
  kind: unknown
  host: string
  port: string
  security: unknown
  username: string
  tenantId: string
  clientId: string
  secret: string // '' = keep the saved one
  folder: string
  processedFolder: string
  invalidFolder: string
  intervalMinutes: string
  enabled: boolean
}

export type ValidMailbox = {
  name: string
  kind: MailboxKind
  host: string
  port: number
  security: 'ssl' | 'starttls'
  username: string
  tenantId: string | null
  clientId: string | null
  folder: string
  processedFolder: string | null
  invalidFolder: string
  intervalMinutes: number
  enabled: boolean
}

const PRINTABLE = /^[^\x00-\x1f\x7f]*$/
const HOSTNAME = /^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/
const IPV4 = /^(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}$/
const ADDRESS = /^[^\s@"<>()\\,;:]{1,64}@[A-Za-z0-9.-]{1,253}$/
// Folder names are quoted by the worker; still, keep them to characters that
// need no escaping in IMAP and no control characters.
const FOLDER = /^[\p{L}\p{N} ._\-\/\[\]&+]{1,200}$/u
const TENANT = /^(?:[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|[A-Za-z0-9][A-Za-z0-9-]{0,62}(?:\.[A-Za-z0-9][A-Za-z0-9-]{0,62})+)$/
const GUID = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/

export function validateMailbox(input: MailboxInput, { secretRequired }: { secretRequired: boolean }): ValidMailbox {
  const bad = (field: string): never => {
    throw new MailRefusal('invalid', field)
  }
  if (!isKind(input.kind)) bad('kind')
  const kind = input.kind as MailboxKind
  const name = input.name.trim()
  if (!name || name.length > 100 || !PRINTABLE.test(name)) bad('name')

  // OAuth mailboxes connect to their provider's IMAP server and nowhere else:
  // the token is only ever sent there.
  let host = KINDS[kind].host ?? input.host.trim().toLowerCase()
  let port = 993
  let security: 'ssl' | 'starttls' = 'ssl'
  if (kind === 'imap') {
    if (!(HOSTNAME.test(host) || IPV4.test(host))) bad('host')
    if (input.security !== 'ssl' && input.security !== 'starttls') bad('security')
    security = input.security as 'ssl' | 'starttls'
    const p = input.port.trim() === '' ? (security === 'ssl' ? 993 : 143) : Number(input.port.trim())
    if (!Number.isInteger(p) || p < 1 || p > 65535 || !/^\d*$/.test(input.port.trim())) bad('port')
    port = p
  } else {
    host = KINDS[kind].host as string
  }

  const username = input.username.trim()
  if (kind === 'imap') {
    if (!username || username.length > 320 || /\s/.test(username) || !PRINTABLE.test(username)) bad('username')
  } else if (!ADDRESS.test(username)) {
    bad('username')
  }

  let tenantId: string | null = null
  let clientId: string | null = null
  if (kind === 'microsoft') {
    tenantId = input.tenantId.trim()
    if (!TENANT.test(tenantId)) bad('tenant_id')
    clientId = input.clientId.trim()
    if (!GUID.test(clientId)) bad('client_id')
  }

  if (input.secret.length > 20000 || (kind !== 'google' && !PRINTABLE.test(input.secret))) bad('secret')
  if (secretRequired && !input.secret) bad('secret')
  if (kind === 'google' && input.secret) checkServiceAccountKey(input.secret, bad)

  const folder = input.folder.trim() || 'INBOX'
  if (!FOLDER.test(folder)) bad('folder')
  const processedFolder = input.processedFolder.trim() || null
  if (processedFolder && (!FOLDER.test(processedFolder) || processedFolder === folder)) bad('processed_folder')
  const invalidFolder = input.invalidFolder.trim() || 'DMARC-Invalid'
  if (!FOLDER.test(invalidFolder) || invalidFolder === folder) bad('invalid_folder')

  const interval = Number(input.intervalMinutes.trim() || '60')
  if (!/^\d*$/.test(input.intervalMinutes.trim()) || !Number.isInteger(interval) || interval < 15 || interval > 1440) bad('interval_minutes')

  return { name, kind, host, port, security, username, tenantId, clientId, folder, processedFolder, invalidFolder, intervalMinutes: interval, enabled: input.enabled }
}

// The key is checked for shape only (it is the worker that signs with it);
// nothing from it is stored outside the encrypted secret.
function checkServiceAccountKey(text: string, bad: (field: string) => never): void {
  let key: unknown
  try {
    key = JSON.parse(text)
  } catch {
    bad('secret')
  }
  const k = key as Record<string, unknown>
  if (
    !k ||
    typeof k !== 'object' ||
    k.type !== 'service_account' ||
    typeof k.client_email !== 'string' ||
    typeof k.private_key !== 'string' ||
    !k.private_key.includes('PRIVATE KEY')
  ) {
    bad('secret')
  }
}

// ---------- changes (admin and above) ----------

async function guarded<T>(
  db: Pool,
  actor: MailActor,
  action: string,
  target: string,
  fn: (c: PoolClient) => Promise<{ result: T; detail: Record<string, unknown>; target?: string }>
): Promise<T> {
  try {
    if (!atLeast(actor.role, 'admin')) throw new MailRefusal('not_allowed')
    const client = await db.connect()
    try {
      await client.query('BEGIN')
      if (actor.userId != null) {
        // The caller as the database sees them now, not as their session said.
        const me = await client.query<{ status: string; role: Role }>(`SELECT status, role FROM users WHERE id = $1`, [actor.userId])
        if (me.rows[0]?.status !== 'active' || !atLeast(me.rows[0].role, 'admin')) throw new MailRefusal('not_allowed')
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
    if (err instanceof MailRefusal) {
      await recordAudit(db, { action: 'action_refused', actor, target, detail: { action, reason: err.code, ...(err.field ? { field: err.field } : {}) } })
    }
    throw err
  }
}

const mailboxContext = (id: number) => `mailbox:${id}`

// What the audit log records about a mailbox: never the secret.
function describe(v: ValidMailbox): Record<string, unknown> {
  return {
    name: v.name,
    kind: v.kind,
    host: v.host,
    port: v.port,
    security: v.security,
    username: v.username,
    tenant_id: v.tenantId,
    client_id: v.clientId,
    folder: v.folder,
    processed_folder: v.processedFolder,
    invalid_folder: v.invalidFolder,
    interval_minutes: v.intervalMinutes,
    enabled: v.enabled,
  }
}

export async function createMailbox(db: Pool, actor: MailActor, input: MailboxInput, env: Env = process.env): Promise<number> {
  return guarded(db, actor, 'mailbox_created', 'mailbox', async (c) => {
    const v = validateMailbox(input, { secretRequired: true })
    const { rows } = await c.query<{ id: string }>(
      `INSERT INTO mailboxes (name, kind, enabled, host, port, security, username, tenant_id, client_id, folder, processed_folder,
         invalid_folder, interval_minutes, created_by, updated_by)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $14) RETURNING id`,
      [v.name, v.kind, v.enabled, v.host, v.port, v.security, v.username, v.tenantId, v.clientId, v.folder, v.processedFolder, v.invalidFolder, v.intervalMinutes, actor.userId]
    )
    const id = Number(rows[0].id)
    await c.query(`UPDATE mailboxes SET secret = $2, secret_updated_at = NOW() WHERE id = $1`, [
      id,
      encryptMailboxSecret(mailboxContext(id), input.secret, env),
    ])
    return { result: id, detail: { ...describe(v), secret: 'set' }, target: `mailbox:${id}` }
  })
}

export async function updateMailbox(db: Pool, actor: MailActor, id: number, input: MailboxInput, env: Env = process.env): Promise<void> {
  await guarded(db, actor, 'mailbox_updated', `mailbox:${id}`, async (c) => {
    const existing = (
      await c.query<{ kind: MailboxKind; has_secret: boolean; host: string; port: number; security: string; username: string; tenant_id: string | null; client_id: string | null }>(
        `SELECT kind, secret IS NOT NULL AS has_secret, host, port, security, username, tenant_id, client_id FROM mailboxes WHERE id = $1 FOR UPDATE`,
        [id]
      )
    ).rows[0]
    if (!existing) throw new MailRefusal('not_found')
    // A saved secret is only ever used where it was entered for: changing the
    // kind, server, account, tenant or application needs it typed again.
    // Otherwise an administrator could point the worker, with the saved
    // password or key, at a server they control or another user's mailbox.
    const v = validateMailbox(input, { secretRequired: false })
    const retargeted =
      v.kind !== existing.kind ||
      v.host !== existing.host ||
      v.port !== Number(existing.port) ||
      v.security !== existing.security ||
      v.username !== existing.username ||
      v.tenantId !== existing.tenant_id ||
      v.clientId !== existing.client_id
    if (!input.secret && (!existing.has_secret || retargeted)) throw new MailRefusal('invalid', 'secret')
    await c.query(
      `UPDATE mailboxes SET name = $2, kind = $3, enabled = $4, host = $5, port = $6, security = $7, username = $8, tenant_id = $9,
         client_id = $10, folder = $11, processed_folder = $12, invalid_folder = $13, interval_minutes = $14,
         updated_at = NOW(), updated_by = $15
       WHERE id = $1`,
      [id, v.name, v.kind, v.enabled, v.host, v.port, v.security, v.username, v.tenantId, v.clientId, v.folder, v.processedFolder, v.invalidFolder, v.intervalMinutes, actor.userId]
    )
    let secret: 'kept' | 'replaced' = 'kept'
    if (input.secret) {
      await c.query(`UPDATE mailboxes SET secret = $2, secret_updated_at = NOW() WHERE id = $1`, [id, encryptMailboxSecret(mailboxContext(id), input.secret, env)])
      secret = 'replaced'
    }
    return { result: undefined, detail: { ...describe(v), secret } }
  })
}

export async function setMailboxEnabled(db: Pool, actor: MailActor, id: number, enabled: boolean): Promise<void> {
  await guarded(db, actor, enabled ? 'mailbox_enabled' : 'mailbox_disabled', `mailbox:${id}`, async (c) => {
    const { rowCount } = await c.query(`UPDATE mailboxes SET enabled = $2, updated_at = NOW(), updated_by = $3 WHERE id = $1`, [id, enabled, actor.userId])
    if (!rowCount) throw new MailRefusal('not_found')
    return { result: undefined, detail: {} }
  })
}

// Its runs stay (ingest_runs.mailbox_id becomes NULL); its jobs go with it.
export async function deleteMailbox(db: Pool, actor: MailActor, id: number): Promise<void> {
  await guarded(db, actor, 'mailbox_deleted', `mailbox:${id}`, async (c) => {
    const { rows } = await c.query<{ name: string; username: string }>(`DELETE FROM mailboxes WHERE id = $1 RETURNING name, username`, [id])
    if (!rows[0]) throw new MailRefusal('not_found')
    return { result: undefined, detail: { name: rows[0].name, username: rows[0].username } }
  })
}

// One waiting job of each kind per mailbox: asking again while one waits
// returns that one.
export async function requestJob(db: Pool, actor: MailActor, id: number, kind: 'test' | 'run'): Promise<number> {
  return guarded(db, actor, kind === 'test' ? 'mailbox_test_requested' : 'mailbox_run_requested', `mailbox:${id}`, async (c) => {
    const mb = await c.query(`SELECT id FROM mailboxes WHERE id = $1 FOR UPDATE`, [id])
    if (!mb.rows[0]) throw new MailRefusal('not_found')
    const waiting = await c.query<{ id: string }>(
      `SELECT id FROM worker_jobs WHERE mailbox_id = $1 AND kind = $2 AND status IN ('queued', 'running') ORDER BY id LIMIT 1`,
      [id, kind]
    )
    if (waiting.rows[0]) return { result: Number(waiting.rows[0].id), detail: { job: Number(waiting.rows[0].id), reused: true } }
    const { rows } = await c.query<{ id: string }>(`INSERT INTO worker_jobs (kind, mailbox_id, requested_by) VALUES ($1, $2, $3) RETURNING id`, [
      kind,
      id,
      actor.userId,
    ])
    return { result: Number(rows[0].id), detail: { job: Number(rows[0].id) } }
  })
}

// ---------- monitored domains ----------

// ALLOWED_DOMAINS, when set, wins over the list saved here (and the worker
// ignores the list), so the list is read-only then.
export function domainsFromEnvironment(env: Env = process.env): string[] | null {
  const raw = env.ALLOWED_DOMAINS
  if (raw == null || raw.trim() === '') return null
  return envList(raw).map((d) => d.toLowerCase())
}

export type DomainRow = { id: number; name: string; created_at: string; created_by_email: string | null }

export async function listDomains(db: Q): Promise<DomainRow[]> {
  const { rows } = await db.query(
    `SELECT d.id::int AS id, d.name, d.created_at, u.email AS created_by_email
     FROM monitored_domains d LEFT JOIN users u ON u.id = d.created_by ORDER BY d.name`
  )
  return rows
}

const DOMAIN = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$/

export function normalizeDomain(raw: string): string | null {
  const d = raw.trim().toLowerCase().replace(/\.$/, '')
  if (!DOMAIN.test(d) || d.endsWith('-')) return null
  return d
}

export async function addDomain(db: Pool, actor: MailActor, raw: string, env: Env = process.env): Promise<void> {
  await guarded(db, actor, 'domain_added', 'domains', async (c) => {
    if (domainsFromEnvironment(env)) throw new MailRefusal('environment')
    const name = normalizeDomain(raw)
    if (!name) throw new MailRefusal('invalid', 'domain')
    const { rowCount } = await c.query(`INSERT INTO monitored_domains (name, created_by) VALUES ($1, $2) ON CONFLICT (name) DO NOTHING`, [name, actor.userId])
    if (!rowCount) throw new MailRefusal('duplicate')
    return { result: undefined, detail: { domain: name }, target: `domain:${name}` }
  })
}

export async function removeDomain(db: Pool, actor: MailActor, id: number, env: Env = process.env): Promise<void> {
  await guarded(db, actor, 'domain_removed', `domain:${id}`, async (c) => {
    if (domainsFromEnvironment(env)) throw new MailRefusal('environment')
    const { rows } = await c.query<{ name: string }>(`DELETE FROM monitored_domains WHERE id = $1 RETURNING name`, [id])
    if (!rows[0]) throw new MailRefusal('not_found')
    return { result: undefined, detail: { domain: rows[0].name }, target: `domain:${rows[0].name}` }
  })
}

// ---------- domains found in reports ----------

export type FoundDomain = {
  name: string
  base_domain: string | null
  reports_seen: number
  first_seen_at: string
  last_seen_at: string
  held: number
  monitored: boolean
}

// Every domain reports were about, with how many reports are held for it
// (domains nobody monitors yet). Grouped by registrable domain in the page.
export async function listFoundDomains(db: Q, env: Env = process.env): Promise<FoundDomain[]> {
  const fromEnv = domainsFromEnvironment(env)
  const { rows } = await db.query<Omit<FoundDomain, 'monitored'> & { in_panel: boolean }>(
    `SELECT f.name, f.base_domain, f.reports_seen, f.first_seen_at, f.last_seen_at,
            (SELECT COUNT(*)::int FROM held_reports h WHERE h.domain = f.name) AS held,
            EXISTS (SELECT 1 FROM monitored_domains m WHERE m.name = f.name) AS in_panel
     FROM discovered_domains f
     ORDER BY COALESCE(f.base_domain, f.name), f.name
     LIMIT 1000`
  )
  return rows.map(({ in_panel, ...r }) => ({ ...r, monitored: fromEnv ? fromEnv.includes(r.name) : in_panel }))
}

// ---------- display ----------

// Run errors quote strangers' emails (subjects, parser messages): shown as
// text (React escapes it), one line, shortened.
export function shortError(e: unknown, max = 300): string {
  const o = (e && typeof e === 'object' ? e : {}) as Record<string, unknown>
  const where = o.uid != null ? `message ${String(o.uid)}` : o.file != null ? String(o.file) : ''
  const raw = [where, o.subject ? `“${String(o.subject)}”` : '', String(o.error ?? o.message ?? '')].filter(Boolean).join(': ')
  // eslint-disable-next-line no-control-regex
  const flat = raw.replace(/[\x00-\x1f\x7f\u2028\u2029]+/g, ' ').replace(/\s+/g, ' ').trim()
  return flat.length > max ? `${flat.slice(0, max - 1)}…` : flat
}
