// Mailboxes and monitored domains configured in the panel, against
// PostgreSQL: who may change them, what is validated, that the secret is
// stored for the worker only and never read back, and what the audit log
// records.

import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest'
import { decrypt } from '@/lib/envelope.mjs'
import { TEST_DATABASE_URL, createSchema } from '../helpers/db'

const SCHEMA = 'dmarcscope_mail_test'
const APP_SECRET = 'mail-test-app-secret-0123456789-abcdefghijk'
const CANARY = 'imap-password-canary-7f3a'

describe.skipIf(!TEST_DATABASE_URL)('mail settings in the panel', () => {
  let db: Awaited<ReturnType<typeof createSchema>>
  let mail: typeof import('@/lib/mail')
  let pool: import('pg').Pool
  const ids: Record<string, number> = {}
  const ADMIN = () => ({ userId: ids.admin, email: 'admin@example.com', ip: null, role: 'admin' as const })
  const VIEWER = () => ({ userId: ids.viewer, email: 'viewer@example.com', ip: null, role: 'viewer' as const })

  const imap = (over: Partial<import('@/lib/mail').MailboxInput> = {}): import('@/lib/mail').MailboxInput => ({
    name: 'Reports',
    kind: 'imap',
    host: 'imap.example.com',
    port: '',
    security: 'ssl',
    username: 'reports@example.com',
    tenantId: '',
    clientId: '',
    secret: CANARY,
    folder: '',
    processedFolder: '',
    invalidFolder: '',
    intervalMinutes: '',
    enabled: true,
    ...over,
  })

  beforeAll(async () => {
    db = await createSchema(SCHEMA)
    Object.assign(process.env, { DATABASE_URL: db.url, APP_SECRET, SETTINGS_CACHE_SECONDS: '0' })
    delete process.env.ALLOWED_DOMAINS
    vi.spyOn(console, 'log').mockImplementation(() => {})
    vi.spyOn(console, 'error').mockImplementation(() => {})
    mail = await import('@/lib/mail')
    pool = (await import('@/lib/db')).getPool()
  })
  afterAll(async () => {
    vi.restoreAllMocks()
    const { closePool } = await import('@/lib/db')
    await closePool()
    await db?.drop()
  })
  beforeEach(async () => {
    delete process.env.ALLOWED_DOMAINS
    await db.admin.query(`TRUNCATE users, mailboxes, monitored_domains, worker_jobs, ingest_runs, discovered_domains, held_reports, worker_heartbeats, ingest_passes RESTART IDENTITY CASCADE`)
    for (const [who, role] of [['admin', 'admin'], ['viewer', 'viewer']] as const) {
      const { rows } = await db.admin.query(`INSERT INTO users (email, role, role_source, status, source) VALUES ($1, $2, 'assigned', 'active', 'oidc') RETURNING id`, [`${who}@example.com`, role])
      ids[who] = Number(rows[0].id)
    }
  })

  it('stores the secret encrypted for the worker, bound to the row, and never reads it back', async () => {
    const id = await mail.createMailbox(pool, ADMIN(), imap())
    const raw = (await db.admin.query(`SELECT secret FROM mailboxes WHERE id = $1`, [id])).rows[0].secret as string
    expect(raw).not.toContain(CANARY)
    // What the worker does: purpose 'mailbox', context bound to this id.
    expect(decrypt({ secrets: [APP_SECRET], purpose: 'mailbox', context: `mailbox:${id}`, envelope: raw }).plaintext).toBe(CANARY)
    expect(() => decrypt({ secrets: [APP_SECRET], purpose: 'mailbox', context: `mailbox:${id + 1}`, envelope: raw })).toThrow()

    // Everything the pages read: no secret, only whether it is set.
    const listed = await mail.listMailboxes(pool)
    const one = await mail.getMailbox(pool, id)
    expect(JSON.stringify([listed, one])).not.toMatch(/canary|secret":"/)
    expect(one).toMatchObject({ secret_set: true, port: 993, folder: 'INBOX', invalid_folder: 'DMARC-Invalid', interval_minutes: 60 })
    expect(one).not.toHaveProperty('secret')

    // The audit log records that it was set, never what it is.
    const audit = await db.admin.query(`SELECT action, detail FROM audit_log WHERE target = $1 ORDER BY id DESC LIMIT 1`, [`mailbox:${id}`])
    expect(audit.rows[0]).toMatchObject({ action: 'mailbox_created', detail: { secret: 'set', host: 'imap.example.com' } })
    expect(JSON.stringify(audit.rows)).not.toContain(CANARY)

    // The web app's own decryption refuses this purpose.
    const { decryptSecret } = await import('@/lib/crypto')
    expect(() => decryptSecret('mailbox' as never, `mailbox:${id}`, raw)).toThrow(/cannot be decrypted by the web app/)
  })

  it('keeps the secret unless a new one is typed, and asks for one when the kind changes', async () => {
    const id = await mail.createMailbox(pool, ADMIN(), imap())
    const before = (await db.admin.query(`SELECT secret FROM mailboxes WHERE id = $1`, [id])).rows[0].secret
    await mail.updateMailbox(pool, ADMIN(), id, imap({ secret: '', name: 'Renamed' }))
    const after = await db.admin.query(`SELECT name, secret FROM mailboxes WHERE id = $1`, [id])
    expect(after.rows[0]).toMatchObject({ name: 'Renamed', secret: before })

    const toMicrosoft = imap({ kind: 'microsoft', secret: '', tenantId: 'contoso.onmicrosoft.com', clientId: '11111111-2222-3333-4444-555555555555' })
    await expect(mail.updateMailbox(pool, ADMIN(), id, toMicrosoft)).rejects.toMatchObject({ code: 'invalid', field: 'secret' })
    await mail.updateMailbox(pool, ADMIN(), id, { ...toMicrosoft, secret: 'client-secret-value', host: 'evil.example' })
    // OAuth kinds always connect to their provider's server: a token is only sent there.
    expect((await mail.getMailbox(pool, id))).toMatchObject({ kind: 'microsoft', host: 'outlook.office365.com', port: 993, security: 'ssl' })
    const audit = await db.admin.query(`SELECT detail FROM audit_log WHERE action = 'mailbox_updated' AND target = $1 ORDER BY id`, [`mailbox:${id}`])
    expect(audit.rows.map((r) => r.detail.secret)).toEqual(['kept', 'replaced'])
  })

  it('never lets a saved secret be sent somewhere else without typing it again', async () => {
    const id = await mail.createMailbox(pool, ADMIN(), imap())
    for (const over of [{ host: 'imap.attacker.example' }, { port: '994' }, { security: 'starttls', port: '993' }, { username: 'other@example.com' }]) {
      await expect(mail.updateMailbox(pool, ADMIN(), id, imap({ ...over, secret: '' })), JSON.stringify(over)).rejects.toMatchObject({ code: 'invalid', field: 'secret' })
    }
    expect(await mail.getMailbox(pool, id)).toMatchObject({ host: 'imap.example.com', username: 'reports@example.com' })
    await mail.updateMailbox(pool, ADMIN(), id, imap({ host: 'imap2.example.com', secret: 'retyped' }))

    const key = JSON.stringify({ type: 'service_account', client_email: 'x@p.iam.gserviceaccount.com', private_key: '-----BEGIN PRIVATE KEY-----\nAAA\n-----END PRIVATE KEY-----\n' })
    const g = await mail.createMailbox(pool, ADMIN(), imap({ kind: 'google', secret: key }))
    await expect(mail.updateMailbox(pool, ADMIN(), g, imap({ kind: 'google', username: 'ceo@example.com', secret: '' }))).rejects.toMatchObject({ field: 'secret' })
    await mail.updateMailbox(pool, ADMIN(), g, imap({ kind: 'google', name: 'Renamed', folder: 'Reports', secret: '' })) // harmless changes keep it

    const ms = { kind: 'microsoft', tenantId: 'contoso.onmicrosoft.com', clientId: '11111111-2222-3333-4444-555555555555' }
    const m = await mail.createMailbox(pool, ADMIN(), imap(ms))
    await expect(mail.updateMailbox(pool, ADMIN(), m, imap({ ...ms, tenantId: 'fabrikam.onmicrosoft.com', secret: '' }))).rejects.toMatchObject({ field: 'secret' })
    await expect(mail.updateMailbox(pool, ADMIN(), m, imap({ ...ms, clientId: '99999999-2222-3333-4444-555555555555', secret: '' }))).rejects.toMatchObject({ field: 'secret' })
    await mail.updateMailbox(pool, ADMIN(), m, imap({ ...ms, intervalMinutes: '120', secret: '' }))
  })

  it('validates every field', async () => {
    const cases: Array<[Partial<import('@/lib/mail').MailboxInput>, string]> = [
      [{ kind: 'pop3' }, 'kind'],
      [{ name: ' ' }, 'name'],
      [{ host: 'https://imap.example.com' }, 'host'],
      [{ host: 'imap example.com' }, 'host'],
      [{ port: '70000' }, 'port'],
      [{ port: '9a' }, 'port'],
      [{ security: 'none' }, 'security'],
      [{ username: 'a b' }, 'username'],
      [{ secret: '' }, 'secret'],
      [{ secret: 'line\nbreak' }, 'secret'],
      [{ folder: 'INBOX"\r\nA1 DELETE INBOX' }, 'folder'],
      [{ processedFolder: 'INBOX' }, 'processed_folder'],
      [{ invalidFolder: 'INBOX' }, 'invalid_folder'],
      [{ intervalMinutes: '5' }, 'interval_minutes'],
      [{ intervalMinutes: '2000' }, 'interval_minutes'],
      [{ kind: 'microsoft', tenantId: 'not a tenant', clientId: '11111111-2222-3333-4444-555555555555' }, 'tenant_id'],
      [{ kind: 'microsoft', tenantId: 'contoso.onmicrosoft.com', clientId: 'app' }, 'client_id'],
      [{ kind: 'microsoft', username: 'not-an-address', tenantId: 'contoso.onmicrosoft.com', clientId: '11111111-2222-3333-4444-555555555555' }, 'username'],
      [{ kind: 'google', secret: '{"type":"authorized_user"}' }, 'secret'],
      [{ kind: 'google', secret: 'not json' }, 'secret'],
    ]
    for (const [over, field] of cases) {
      await expect(mail.createMailbox(pool, ADMIN(), imap(over)), JSON.stringify(over)).rejects.toMatchObject({ code: 'invalid', field })
    }
    const key = JSON.stringify({ type: 'service_account', client_email: 'x@p.iam.gserviceaccount.com', private_key: '-----BEGIN PRIVATE KEY-----\nAAA\n-----END PRIVATE KEY-----\n' })
    const g = await mail.createMailbox(pool, ADMIN(), imap({ kind: 'google', secret: key }))
    expect(await mail.getMailbox(pool, g)).toMatchObject({ host: 'imap.gmail.com', secret_set: true })
    expect((await db.admin.query(`SELECT COUNT(*)::int AS n FROM mailboxes`)).rows[0].n).toBe(1)
  })

  it('is for administrators, as the database knows them now', async () => {
    const mark = Number((await db.admin.query(`SELECT COALESCE(MAX(id), 0) AS n FROM audit_log`)).rows[0].n)
    await expect(mail.createMailbox(pool, VIEWER(), imap())).rejects.toMatchObject({ code: 'not_allowed' })
    // A session that still says admin, for someone demoted meanwhile.
    await db.admin.query(`UPDATE users SET role = 'viewer' WHERE id = $1`, [ids.admin])
    await expect(mail.createMailbox(pool, ADMIN(), imap())).rejects.toMatchObject({ code: 'not_allowed' })
    await expect(mail.addDomain(pool, ADMIN(), 'example.com')).rejects.toMatchObject({ code: 'not_allowed' })
    const refused = await db.admin.query(`SELECT detail FROM audit_log WHERE action = 'action_refused' AND id > $1 ORDER BY id`, [mark])
    expect(refused.rows.map((r) => r.detail.action)).toEqual(['mailbox_created', 'mailbox_created', 'domain_added'])
    expect((await db.admin.query(`SELECT COUNT(*)::int AS n FROM mailboxes`)).rows[0].n).toBe(0)
  })

  it('queues one job of each kind at a time for the worker', async () => {
    const id = await mail.createMailbox(pool, ADMIN(), imap())
    const a = await mail.requestJob(pool, ADMIN(), id, 'test')
    const b = await mail.requestJob(pool, ADMIN(), id, 'test')
    const c = await mail.requestJob(pool, ADMIN(), id, 'run')
    expect(b).toBe(a)
    expect(c).not.toBe(a)
    await db.admin.query(`UPDATE worker_jobs SET status = 'done', result = '{"ok":true,"message":"fine"}' WHERE id = $1`, [a])
    expect(await mail.requestJob(pool, ADMIN(), id, 'test')).not.toBe(a)
    const jobs = await mail.listJobs(pool, id)
    expect(jobs.map((j) => [j.kind, j.status])).toEqual([
      ['test', 'queued'],
      ['run', 'queued'],
      ['test', 'done'],
    ])
    expect(jobs[0].requested_by_email).toBe('admin@example.com')
    await expect(mail.requestJob(pool, ADMIN(), id + 99, 'run')).rejects.toMatchObject({ code: 'not_found' })

    // Deleting the mailbox takes its jobs; its runs stay, unattached.
    await db.admin.query(`INSERT INTO ingest_runs (mailbox_id, trigger, finished_at) VALUES ($1, 'manual', NOW())`, [id])
    await mail.deleteMailbox(pool, ADMIN(), id)
    expect((await db.admin.query(`SELECT COUNT(*)::int AS n FROM worker_jobs`)).rows[0].n).toBe(0)
    expect((await db.admin.query(`SELECT mailbox_id FROM ingest_runs`)).rows).toEqual([{ mailbox_id: null }])
  })

  it('fails a request that could not be started, but never one a worker has taken', async () => {
    const id = await mail.createMailbox(pool, ADMIN(), imap())
    const queued = await mail.requestJob(pool, ADMIN(), id, 'test')
    const taken = await mail.requestJob(pool, ADMIN(), id, 'run')
    await db.admin.query(`UPDATE worker_jobs SET status = 'running' WHERE id = $1`, [taken])
    await mail.failQueuedJob(pool, queued, 'Could not start the test: refused.')
    await mail.failQueuedJob(pool, taken, 'Could not start the run: refused.')
    const jobs = await mail.listJobs(pool, id)
    expect(jobs.map((j) => [j.kind, j.status, j.result?.message ?? null])).toEqual([
      ['run', 'running', null],
      ['test', 'failed', 'Could not start the test: refused.'],
    ])
  })

  it('lists the domains found in reports, with held reports, and counts only long-running workers', async () => {
    await mail.addDomain(pool, ADMIN(), 'example.com')
    await db.admin.query(
      `INSERT INTO discovered_domains (name, base_domain, reports_seen) VALUES ('example.com', 'example.com', 3), ('mail.example.com', 'example.com', 2), ('other.test', NULL, 1)`
    )
    await db.admin.query(`INSERT INTO held_reports (domain, org_name, report_id, report) VALUES ('mail.example.com', 'google.com', 'r1', '{}'), ('mail.example.com', 'google.com', 'r2', '{}')`)
    const found = await mail.listFoundDomains(pool, {})
    expect(found.map((d) => [d.name, d.base_domain, d.reports_seen, d.held, d.monitored])).toEqual([
      ['example.com', 'example.com', 3, 0, true],
      ['mail.example.com', 'example.com', 2, 2, false],
      ['other.test', null, 1, 0, false],
    ])
    // ALLOWED_DOMAINS decides what is monitored when it is set.
    expect((await mail.listFoundDomains(pool, { ALLOWED_DOMAINS: 'other.test' })).map((d) => d.monitored)).toEqual([false, false, true])

    await db.admin.query(`INSERT INTO worker_heartbeats (worker_id, mode) VALUES ('vercel-pass', 'pass')`)
    expect((await mail.workerStatus(pool)).alive).toBe(0)
    await db.admin.query(`INSERT INTO worker_heartbeats (worker_id) VALUES ('serve-1')`)
    expect((await mail.workerStatus(pool)).alive).toBe(1)
  })

  it('shows run history and whether a worker is alive', async () => {
    const id = await mail.createMailbox(pool, ADMIN(), imap({ intervalMinutes: '30' }))
    expect((await mail.getMailbox(pool, id))?.last_run).toBeNull()
    await db.admin.query(
      `INSERT INTO ingest_runs (mailbox_id, trigger, started_at, finished_at, failed, messages_fetched, errors)
       VALUES ($1, 'schedule', NOW() - interval '10 minutes', NOW() - interval '9 minutes', TRUE, 2, $2)`,
      [id, JSON.stringify([{ uid: '7', error: 'not a valid DMARC report: <script>alert(1)</script>\nsecond line' }])]
    )
    const m = await mail.getMailbox(pool, id)
    expect(m?.last_run).toMatchObject({ failed: true, trigger: 'schedule', messages_fetched: 2 })
    const next = new Date(m!.next_run_at!).getTime() - Date.now()
    expect(next).toBeGreaterThan(15 * 60_000)
    expect(next).toBeLessThan(21 * 60_000)
    expect(mail.shortError(m!.last_run!.errors![0])).toBe('message 7: not a valid DMARC report: <script>alert(1)</script> second line')
    expect(mail.shortError({ error: 'x'.repeat(1000) }).length).toBe(300)

    expect(await mail.workerStatus(pool)).toMatchObject({ alive: 0, lastSeen: null })
    await db.admin.query(`INSERT INTO worker_heartbeats (worker_id, hostname, version) VALUES ('w1', 'h', '2.0.0')`)
    await db.admin.query(`INSERT INTO worker_heartbeats (worker_id, hostname, version, seen_at) VALUES ('w0', 'h', '2.0.0', NOW() - interval '1 hour')`)
    expect(await mail.workerStatus(pool)).toMatchObject({ alive: 1, versions: ['2.0.0'] })
  })

  it('manages monitored domains, read-only while ALLOWED_DOMAINS is set', async () => {
    const mark = Number((await db.admin.query(`SELECT COALESCE(MAX(id), 0) AS n FROM audit_log`)).rows[0].n)
    await mail.addDomain(pool, ADMIN(), ' Example.COM. ')
    await expect(mail.addDomain(pool, ADMIN(), 'example.com')).rejects.toMatchObject({ code: 'duplicate' })
    for (const bad of ['example', '-x.example.com', 'exa mple.com', 'http://example.com', 'a'.repeat(64) + '.com']) {
      await expect(mail.addDomain(pool, ADMIN(), bad), bad).rejects.toMatchObject({ code: 'invalid', field: 'domain' })
    }
    await mail.addDomain(pool, ADMIN(), 'xn--bcher-kva.example')
    expect((await mail.listDomains(pool)).map((d) => d.name)).toEqual(['example.com', 'xn--bcher-kva.example'])

    process.env.ALLOWED_DOMAINS = 'env.example, Other.example'
    expect(mail.domainsFromEnvironment()).toEqual(['env.example', 'other.example'])
    await expect(mail.addDomain(pool, ADMIN(), 'new.example')).rejects.toMatchObject({ code: 'environment' })
    const [first] = await mail.listDomains(pool)
    await expect(mail.removeDomain(pool, ADMIN(), first.id)).rejects.toMatchObject({ code: 'environment' })
    delete process.env.ALLOWED_DOMAINS
    await mail.removeDomain(pool, ADMIN(), first.id)
    const actions = (await db.admin.query(`SELECT action, target FROM audit_log WHERE action LIKE 'domain_%' AND id > $1 ORDER BY id`, [mark])).rows
    expect(actions).toEqual([
      { action: 'domain_added', target: 'domain:example.com' },
      { action: 'domain_added', target: 'domain:xn--bcher-kva.example' },
      { action: 'domain_removed', target: 'domain:example.com' },
    ])
  })
})
