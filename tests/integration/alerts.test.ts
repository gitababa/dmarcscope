// Alerting against PostgreSQL: evaluation, deduplication, reminders,
// resolution, the delivery outbox and its failure handling, and the panel's
// rules (who may change what, what is stored and shown).

import { createHmac } from 'node:crypto'
import http from 'node:http'
import type { AddressInfo } from 'node:net'
import pg from 'pg'
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest'
import { encrypt } from '@/lib/envelope.mjs'
import { TEST_DATABASE_URL, createSchema } from '../helpers/db'
import { makeCert, startSmtp } from '../helpers/smtp-server'

const SCHEMA = 'dmarcscope_alerts_test'
const APP_SECRET = 'alerts-test-app-secret-0123456789-abcdefghij'
const URL_CANARY = 'https://hooks.example.com/services/T000/B000/canary-url-token'
const SIGNING = 'signing-secret-canary-0123456789'

describe.skipIf(!TEST_DATABASE_URL)('alerts', () => {
  let db: Awaited<ReturnType<typeof createSchema>>
  let pool: pg.Pool
  let evaluate: typeof import('@/lib/alerts/evaluate')
  let deliver: typeof import('@/lib/alerts/deliver')
  let admin: typeof import('@/lib/alerts/admin')
  const ids: Record<string, number> = {}
  const ADMIN = () => ({ userId: ids.admin, email: 'admin@example.com', ip: null, role: 'admin' as const })
  const VIEWER = () => ({ userId: ids.viewer, email: 'viewer@example.com', ip: null, role: 'viewer' as const })

  // A receiver for webhook and Slack channels.
  let receiver: http.Server
  let base: string
  const hits: Array<{ url?: string; headers: http.IncomingHttpHeaders; body: string }> = []
  let respond = 200

  beforeAll(async () => {
    db = await createSchema(SCHEMA)
    Object.assign(process.env, { DATABASE_URL: db.url, APP_SECRET, SETTINGS_CACHE_SECONDS: '0' })
    vi.spyOn(console, 'log').mockImplementation(() => {})
    vi.spyOn(console, 'error').mockImplementation(() => {})
    evaluate = await import('@/lib/alerts/evaluate')
    deliver = await import('@/lib/alerts/deliver')
    admin = await import('@/lib/alerts/admin')
    pool = (await import('@/lib/db')).getPool()
    receiver = http.createServer((req, res) => {
      let body = ''
      req.on('data', (c) => (body += c))
      req.on('end', () => {
        hits.push({ url: req.url, headers: req.headers, body })
        res.writeHead(respond)
        res.end()
      })
    })
    await new Promise<void>((r) => receiver.listen(0, '127.0.0.1', r))
    base = `http://127.0.0.1:${(receiver.address() as AddressInfo).port}`
  })
  afterAll(async () => {
    vi.restoreAllMocks()
    await new Promise<void>((r) => receiver?.close(() => r()))
    const { closePool } = await import('@/lib/db')
    await closePool()
    await db?.drop()
  })

  const q = (sql: string, params: unknown[] = []) => db.admin.query(sql, params)
  const one = async (sql: string, params: unknown[] = []) => (await q(sql, params)).rows[0]

  beforeEach(async () => {
    hits.length = 0
    respond = 200
    await q(`TRUNCATE users, alert_channels, alert_rules, alert_events, alert_deliveries, domains, ingest_runs, audit_log RESTART IDENTITY CASCADE`)
    for (const [who, role] of [['admin', 'admin'], ['viewer', 'viewer']] as const) {
      const { rows } = await q(`INSERT INTO users (email, role, role_source, status, source) VALUES ($1, $2, 'assigned', 'active', 'oidc') RETURNING id`, [`${who}@example.com`, role])
      ids[who] = Number(rows[0].id)
    }
  })

  // ---------- seed helpers ----------
  async function domain(name: string): Promise<number> {
    return Number((await one(`INSERT INTO domains (name) VALUES ($1) ON CONFLICT (name) DO UPDATE SET name = EXCLUDED.name RETURNING id`, [name])).id)
  }
  let reportSeq = 0
  async function records(domainName: string, rows: Array<{ ip: string; count: number; aligned: boolean; daysAgo: number }>) {
    const d = await domain(domainName)
    for (const r of rows) {
      reportSeq++
      const rep = await one(
        `INSERT INTO reports (domain_id, org_name, report_id, begin_date, end_date, policy_published)
         VALUES ($1, 'org', $2, NOW() - make_interval(days => $3::int + 1), NOW() - make_interval(days => $3::int), '{}'::jsonb) RETURNING id`,
        [d, `r${reportSeq}`, r.daysAgo]
      )
      await q(
        `INSERT INTO records (report_id, domain_id, source_ip, message_count, dmarc_aligned, period_start, period_end)
         VALUES ($1, $2, $3, $4, $5, NOW() - make_interval(days => $6::int + 1), NOW() - make_interval(days => $6::int))`,
        [rep.id, d, r.ip, r.count, r.aligned, r.daysAgo]
      )
    }
  }
  const dnsCheck = async (domainName: string, results: unknown, minutesAgo: number) =>
    q(`INSERT INTO dns_checks (domain_id, results, checked_at) VALUES ($1, $2::jsonb, NOW() - make_interval(mins => $3::int))`, [await domain(domainName), JSON.stringify(results), minutesAgo])

  async function channel(kind: 'webhook' | 'slack' | 'email', over: Record<string, unknown> = {}): Promise<number> {
    return admin.createChannel(pool, ADMIN(), {
      name: `${kind} channel`, kind, recipients: 'ops@example.com', url: `${base}/${kind}`, signingSecret: SIGNING, enabled: true, ...over,
    } as import('@/lib/alerts/admin').ChannelInput)
  }
  async function rule(kind: string, channelIds: number[], over: Record<string, unknown> = {}): Promise<number> {
    return admin.createRule(pool, ADMIN(), {
      name: `rule ${kind}`, kind, domain: '', minMessages: '', windowDays: '', thresholdPct: '', quietMinutes: '', notifyResolved: false, enabled: true, channelIds, ...over,
    } as import('@/lib/alerts/admin').RuleInput)
  }
  const evalAll = () => evaluate.evaluateAll(pool, { staleHours: 36 })
  const send = (o: Parameters<typeof deliver.deliverDue>[1] = {}) => deliver.deliverDue(pool, { allowPrivate: true, appName: 'DMARCscope', appUrl: 'https://dmarc.example.com', ...o })
  const events = async () => (await q(`SELECT * FROM alert_events ORDER BY id`)).rows
  const deliveries = async () => (await q(`SELECT * FROM alert_deliveries ORDER BY id`)).rows

  // ---------- evaluation ----------

  describe('new source failing', () => {
    it('opens one event per new failing source over the threshold, and ignores the rest', async () => {
      const ch = await channel('slack')
      await rule('new_failing_source', [ch])
      await records('example.com', [
        { ip: '192.0.2.10', count: 500, aligned: false, daysAgo: 1 }, // new, failing: alert
        { ip: '192.0.2.11', count: 20, aligned: false, daysAgo: 1 }, // new, below threshold
        { ip: '192.0.2.12', count: 500, aligned: true, daysAgo: 1 }, // new but passing
        { ip: '192.0.2.13', count: 500, aligned: false, daysAgo: 1 }, // failing now...
        { ip: '192.0.2.13', count: 5, aligned: true, daysAgo: 20 }, // ...but seen long ago: not new
      ])
      const r = await evalAll()
      expect(r).toMatchObject({ ran: true, rules: 1, opened: 1, failed: 0 })
      const ev = await events()
      expect(ev).toHaveLength(1)
      expect(ev[0]).toMatchObject({ dedupe_key: 'example.com|192.0.2.10', state: 'open', domain: 'example.com' })
      expect((await deliveries()).map((d) => [d.kind, d.status])).toEqual([['alert', 'queued']])
    })

    it('sends nothing more when evaluated again, and resolves when the condition is gone', async () => {
      const ch = await channel('slack')
      const id = await rule('new_failing_source', [ch], { notifyResolved: true })
      await records('example.com', [{ ip: '192.0.2.10', count: 500, aligned: false, daysAgo: 1 }])
      await evalAll()
      await evalAll()
      await evalAll()
      expect(await events()).toHaveLength(1)
      expect(await deliveries()).toHaveLength(1)
      await q(`DELETE FROM records`)
      const r = await evalAll()
      expect(r.resolved).toBe(1)
      expect((await events())[0]).toMatchObject({ state: 'resolved' })
      expect((await deliveries()).map((d) => d.kind)).toEqual(['alert', 'resolved'])
      // A recurrence is a new event.
      await records('example.com', [{ ip: '192.0.2.10', count: 500, aligned: false, daysAgo: 1 }])
      await evalAll()
      expect(await events()).toHaveLength(2)
      expect(id).toBeGreaterThan(0)
    })

    it('does not send a resolved notice unless asked', async () => {
      await rule('new_failing_source', [await channel('slack')])
      await records('example.com', [{ ip: '192.0.2.10', count: 500, aligned: false, daysAgo: 1 }])
      await evalAll()
      await q(`DELETE FROM records`)
      await evalAll()
      expect((await deliveries()).map((d) => d.kind)).toEqual(['alert'])
    })
  })

  describe('compliance below a threshold', () => {
    it('gives no verdict below the minimum volume, fires below the threshold, resolves on recovery', async () => {
      await rule('compliance_drop', [await channel('slack')], { thresholdPct: '95', minMessages: '100' })
      await records('few.example', [{ ip: '192.0.2.1', count: 10, aligned: false, daysAgo: 1 }]) // 0%, but 10 messages
      await records('bad.example', [{ ip: '192.0.2.2', count: 900, aligned: true, daysAgo: 1 }, { ip: '192.0.2.3', count: 100, aligned: false, daysAgo: 1 }]) // 90%
      await records('good.example', [{ ip: '192.0.2.4', count: 990, aligned: true, daysAgo: 1 }, { ip: '192.0.2.5', count: 10, aligned: false, daysAgo: 1 }]) // 99%
      await evalAll()
      const ev = await events()
      expect(ev.map((e) => e.dedupe_key)).toEqual(['bad.example'])
      expect(ev[0].summary).toMatch(/90\.0%/)
      await records('bad.example', [{ ip: '192.0.2.2', count: 9000, aligned: true, daysAgo: 0 }])
      await evalAll()
      expect((await events())[0].state).toBe('resolved')
    })

    it('can be limited to one domain', async () => {
      await rule('compliance_drop', [await channel('slack')], { domain: 'bad.example' })
      await records('bad.example', [{ ip: '192.0.2.2', count: 500, aligned: false, daysAgo: 1 }])
      await records('worse.example', [{ ip: '192.0.2.3', count: 500, aligned: false, daysAgo: 1 }])
      await evalAll()
      expect((await events()).map((e) => e.domain)).toEqual(['bad.example'])
    })
  })

  describe('ingest stale', () => {
    it('is not stale on a fresh install, and fires when the last success is older than the window', async () => {
      await rule('ingest_stale', [await channel('slack')])
      await evalAll()
      expect(await events()).toHaveLength(0)
      await q(`INSERT INTO ingest_runs (started_at, finished_at, failed) VALUES (NOW() - INTERVAL '3 days', NOW() - INTERVAL '3 days', FALSE)`)
      await evalAll()
      expect((await events()).map((e) => [e.dedupe_key, e.state])).toEqual([['ingest', 'open']])
      await q(`INSERT INTO ingest_runs (started_at, finished_at, failed) VALUES (NOW(), NOW(), FALSE)`)
      await evalAll()
      expect((await events())[0].state).toBe('resolved')
    })
  })

  describe('record changed', () => {
    it('fires on a change between the latest two checks, not on a failed lookup or a single check', async () => {
      await rule('dns_changed', [await channel('slack')])
      await dnsCheck('one.example', { dmarc: { status: 'ok', record: 'v=DMARC1; p=none' }, spf: { status: 'ok', record: null } }, 5)
      await dnsCheck('flaky.example', { dmarc: { status: 'ok', record: 'v=DMARC1; p=none' } }, 60)
      await dnsCheck('flaky.example', { dmarc: { status: 'fail', record: null, lookup_failed: true } }, 5)
      await dnsCheck('changed.example', { dmarc: { status: 'ok', record: 'v=DMARC1; p=reject' } }, 60)
      await dnsCheck('changed.example', { dmarc: { status: 'warn', record: 'v=DMARC1; p=none' } }, 5)
      await evalAll()
      expect((await events()).map((e) => e.domain)).toEqual(['changed.example'])
      // The next check agrees with the new record: the event clears.
      await dnsCheck('changed.example', { dmarc: { status: 'warn', record: 'v=DMARC1; p=none' } }, 1)
      await evalAll()
      expect((await events())[0].state).toBe('resolved')
    })
  })

  describe('quiet periods', () => {
    it('reminds after the quiet period, at most three times', async () => {
      await rule('ingest_stale', [await channel('slack')], { quietMinutes: '60' })
      await q(`INSERT INTO ingest_runs (started_at, finished_at, failed) VALUES (NOW() - INTERVAL '3 days', NOW() - INTERVAL '3 days', FALSE)`)
      await evalAll()
      await evalAll() // inside the quiet period: nothing
      expect(await deliveries()).toHaveLength(1)
      for (let i = 0; i < 5; i++) {
        await q(`UPDATE alert_events SET last_notified_at = NOW() - INTERVAL '2 hours'`)
        await evalAll()
      }
      expect((await deliveries()).map((d) => d.kind)).toEqual(['alert', 'reminder', 'reminder', 'reminder'])
    })
  })

  describe('isolation and leader safety', () => {
    it('records a failing rule and still evaluates the others', async () => {
      const ch = await channel('slack')
      const bad = await rule('new_failing_source', [ch])
      await q(`UPDATE alert_rules SET params = '{"min_messages": 1e30, "window_days": 7}'::jsonb WHERE id = $1`, [bad])
      await rule('ingest_stale', [ch])
      await q(`INSERT INTO ingest_runs (started_at, finished_at, failed) VALUES (NOW() - INTERVAL '3 days', NOW() - INTERVAL '3 days', FALSE)`)
      const r = await evalAll()
      expect(r).toMatchObject({ rules: 2, failed: 1, opened: 1 })
      expect((await one(`SELECT last_error FROM alert_rules WHERE id = $1`, [bad])).last_error).toBeTruthy()
      expect((await one(`SELECT last_error FROM alert_evaluator`)).last_error).toMatch(/1 rule/)
    })

    it('lets only one evaluation run at a time', async () => {
      const other = new pg.Client({ connectionString: db.url })
      await other.connect()
      try {
        await other.query(`SELECT pg_advisory_lock(5000005)`)
        expect(await evalAll()).toMatchObject({ ran: false })
        await other.query(`SELECT pg_advisory_unlock(5000005)`)
        expect(await evalAll()).toMatchObject({ ran: true })
      } finally {
        await other.end()
      }
    })

    it('makes no outbound call and writes nothing with no rules', async () => {
      await channel('webhook')
      const r = await evalAll()
      expect(r).toMatchObject({ ran: true, rules: 0, opened: 0 })
      expect(await send()).toEqual({ sent: 0, failed: 0, retried: 0 })
      expect(hits).toHaveLength(0)
    })
  })

  // ---------- delivery ----------

  describe('delivery', () => {
    async function fire(channelIds: number[], over: Record<string, unknown> = {}) {
      await rule('ingest_stale', channelIds, over)
      await q(`INSERT INTO ingest_runs (started_at, finished_at, failed) VALUES (NOW() - INTERVAL '3 days', NOW() - INTERVAL '3 days', FALSE)`)
      await evalAll()
    }

    it('posts a signed webhook with a stable event id', async () => {
      await fire([await channel('webhook')])
      expect(await send()).toMatchObject({ sent: 1, failed: 0 })
      const h = hits[0]
      expect(h.url).toBe('/webhook')
      const ts = h.headers['x-dmarcscope-timestamp'] as string
      expect(h.headers['x-dmarcscope-signature']).toBe(`v1=${createHmac('sha256', SIGNING).update(`${ts}.${h.body}`).digest('hex')}`)
      expect(h.headers['x-dmarcscope-event-id']).toBe(String((await events())[0].id))
      expect(JSON.parse(h.body)).toMatchObject({ type: 'alert', rule: { kind: 'ingest_stale' }, event_id: (await events())[0].id })
      expect((await deliveries())[0]).toMatchObject({ status: 'sent', attempts: 1, error: null })
    })

    it('posts a Slack-compatible message', async () => {
      await fire([await channel('slack')])
      await send()
      expect(JSON.parse(hits[0].body).text).toMatch(/Alert: rule ingest_stale/)
    })

    it('sends email through the configured SMTP server', async () => {
      const cert = makeCert()
      const smtp = await startSmtp({ mode: 'ssl', ...cert })
      try {
        await fire([await channel('email')])
        await send({ smtp: async () => ({ host: '127.0.0.1', port: smtp.port, security: 'ssl', username: 'u', password: 'p', from: 'alerts@example.com' }), smtpCa: cert.cert })
        expect(smtp.received[0].rcpt).toEqual(['<ops@example.com>'])
        expect((await deliveries())[0].status).toBe('sent')
      } finally {
        await smtp.close()
        cert.cleanup()
      }
    })

    it('fails permanently, without retrying, when SMTP is not configured', async () => {
      await fire([await channel('email')])
      await send({ smtp: async () => null })
      expect((await deliveries())[0]).toMatchObject({ status: 'failed', attempts: 1 })
      expect((await deliveries())[0].error).toMatch(/SMTP is not configured/)
    })

    it('retries a failing receiver with backoff, then gives up after four attempts, without blocking other channels', async () => {
      const good = await channel('slack', { name: 'good', url: `${base}/good` })
      const bad = await channel('webhook', { name: 'bad', url: 'http://127.0.0.1:9/never' })
      await fire([good, bad])
      let r = await send()
      expect(r).toMatchObject({ sent: 1, retried: 1 })
      const waiting = await one(`SELECT attempts, status, next_attempt_at > NOW() AS later FROM alert_deliveries WHERE channel_id = $1`, [bad])
      expect(waiting).toMatchObject({ attempts: 1, status: 'queued', later: true })
      for (let i = 0; i < 3; i++) {
        await q(`UPDATE alert_deliveries SET next_attempt_at = NOW() WHERE status = 'queued'`)
        r = await send()
      }
      expect(r).toMatchObject({ failed: 1 })
      expect(await one(`SELECT status, attempts FROM alert_deliveries WHERE channel_id = $1`, [bad])).toMatchObject({ status: 'failed', attempts: 4 })
    })

    it('treats a non-2xx answer as a failure', async () => {
      respond = 500
      await fire([await channel('slack')])
      await send()
      expect((await deliveries())[0]).toMatchObject({ status: 'queued', attempts: 1 })
      expect((await deliveries())[0].error).toMatch(/HTTP 500/)
    })

    it('refuses private destinations unless an owner allowed them, on every delivery', async () => {
      await fire([await channel('slack')])
      await send({ allowPrivate: false })
      const d = (await deliveries())[0]
      expect(d.status).toBe('queued')
      expect(d.error).toMatch(/refused/)
      expect(hits).toHaveLength(0)
    })

    it('sends each delivery once when two senders run at once', async () => {
      for (let i = 0; i < 6; i++) await channel('slack', { name: `c${i}`, url: `${base}/c${i}` })
      const all = (await q(`SELECT id FROM alert_channels`)).rows.map((r) => Number(r.id))
      await fire(all)
      await Promise.all([send(), send(), send()])
      expect(hits.map((h) => h.url).sort()).toEqual(['/c0', '/c1', '/c2', '/c3', '/c4', '/c5'])
    })

    it('cancels a delivery whose channel is disabled, and one whose condition cleared', async () => {
      const ch = await channel('slack')
      await fire([ch])
      await q(`UPDATE alert_channels SET enabled = FALSE`)
      await send()
      expect((await deliveries())[0]).toMatchObject({ status: 'failed' })
      expect((await deliveries())[0].error).toMatch(/disabled/)

      await q(`UPDATE alert_channels SET enabled = TRUE`)
      await q(`INSERT INTO alert_deliveries (event_id, channel_id, kind) SELECT id, $1, 'alert' FROM alert_events`, [ch])
      await q(`UPDATE alert_events SET state = 'resolved', resolved_at = NOW()`)
      await send()
      expect((await deliveries())[1].error).toMatch(/cleared/)
      expect(hits).toHaveLength(0)
    })

    it('fails without retrying when the saved secret cannot be decrypted (APP_SECRET changed)', async () => {
      const ch = await channel('slack')
      await q(`UPDATE alert_channels SET secret = $2 WHERE id = $1`, [ch, encrypt({ secret: 'some-other-app-secret-0123456789-abcdefgh', purpose: 'alert', context: `alert:${ch}`, plaintext: JSON.stringify({ url: `${base}/x` }) })])
      await fire([ch])
      await send()
      expect((await deliveries())[0]).toMatchObject({ status: 'failed', attempts: 1 })
      expect((await deliveries())[0].error).toMatch(/cannot be decrypted/)
    })

    it('sends a test and records it in the history, rate limited per channel', async () => {
      const ch = await channel('slack')
      await admin.requestTest(pool, ADMIN(), ch)
      await send()
      expect(JSON.parse(hits[0].body).text).toMatch(/Test: Test notification/)
      expect((await deliveries())[0]).toMatchObject({ kind: 'test', status: 'sent', event_id: null })
      await expect(admin.requestTest(pool, ADMIN(), ch)).rejects.toMatchObject({ code: 'rate_limited' })
    })
  })

  // ---------- the panel ----------

  describe('changes in the panel', () => {
    it('refuses a viewer, and records the refusal', async () => {
      await expect(admin.createChannel(pool, VIEWER(), { name: 'x', kind: 'email', recipients: 'a@example.com', url: '', signingSecret: '', enabled: true })).rejects.toMatchObject({ code: 'not_allowed' })
      expect((await one(`SELECT COUNT(*)::int AS n FROM alert_channels`)).n).toBe(0)
      expect(await one(`SELECT action, detail FROM audit_log WHERE action = 'action_refused'`)).toMatchObject({ detail: { action: 'alert_channel_created', reason: 'not_allowed' } })
    })

    it('refuses someone demoted since their session was issued', async () => {
      await q(`UPDATE users SET role = 'viewer' WHERE id = $1`, [ids.admin])
      await expect(admin.createRule(pool, ADMIN(), { name: 'x', kind: 'ingest_stale', domain: '', minMessages: '', windowDays: '', thresholdPct: '', quietMinutes: '', notifyResolved: false, enabled: true, channelIds: [] })).rejects.toMatchObject({ code: 'not_allowed' })
    })

    it('stores a channel address encrypted and bound to the row, shows only whether it is set, and audits it as set', async () => {
      const ch = await channel('webhook', { url: URL_CANARY })
      const raw = (await one(`SELECT secret FROM alert_channels WHERE id = $1`, [ch])).secret as string
      expect(raw).not.toContain('canary')
      const { decrypt } = await import('@/lib/envelope.mjs')
      expect(JSON.parse(decrypt({ secrets: [APP_SECRET], purpose: 'alert', context: `alert:${ch}`, envelope: raw }).plaintext)).toEqual({ url: URL_CANARY, signing_secret: SIGNING })
      expect(() => decrypt({ secrets: [APP_SECRET], purpose: 'alert', context: `alert:${ch + 1}`, envelope: raw })).toThrow()

      const listed = await admin.listChannels(pool)
      expect(JSON.stringify(listed)).not.toMatch(/canary|signing/i)
      expect(listed[0]).toMatchObject({ secret_set: true, host: 'hooks.example.com' })
      expect(listed[0]).not.toHaveProperty('secret')
      expect(JSON.stringify((await q(`SELECT detail FROM audit_log`)).rows)).not.toMatch(/canary|signing/i)
    })

    it('replaces a channel address only together with its signing secret, and keeps both otherwise', async () => {
      const ch = await channel('webhook')
      const before = (await one(`SELECT secret FROM alert_channels WHERE id = $1`, [ch])).secret
      await admin.updateChannel(pool, ADMIN(), ch, { name: 'Renamed', kind: 'webhook', recipients: '', url: '', signingSecret: '', enabled: true })
      expect(await one(`SELECT name, secret FROM alert_channels WHERE id = $1`, [ch])).toMatchObject({ name: 'Renamed', secret: before })
      await expect(admin.updateChannel(pool, ADMIN(), ch, { name: 'x', kind: 'webhook', recipients: '', url: 'https://other.example/x', signingSecret: '', enabled: true })).rejects.toMatchObject({ code: 'invalid', field: 'signing_secret' })
      expect((await one(`SELECT secret FROM alert_channels WHERE id = $1`, [ch])).secret).toBe(before)
      // The kind cannot be changed by an update.
      await admin.updateChannel(pool, ADMIN(), ch, { name: 'x', kind: 'email', recipients: 'a@example.com', url: '', signingSecret: '', enabled: true })
      expect((await one(`SELECT kind FROM alert_channels WHERE id = $1`, [ch])).kind).toBe('webhook')
    })

    it('deleting a channel removes its queued deliveries; deleting a rule removes its events', async () => {
      const ch = await channel('slack')
      const r = await rule('ingest_stale', [ch])
      await q(`INSERT INTO ingest_runs (started_at, finished_at, failed) VALUES (NOW() - INTERVAL '3 days', NOW() - INTERVAL '3 days', FALSE)`)
      await evalAll()
      await admin.deleteChannel(pool, ADMIN(), ch)
      expect(await deliveries()).toHaveLength(0)
      await admin.deleteRule(pool, ADMIN(), r)
      expect(await events()).toHaveLength(0)
      await expect(admin.deleteRule(pool, ADMIN(), r)).rejects.toMatchObject({ code: 'not_found' })
    })

    it('refuses a rule that names a channel that does not exist', async () => {
      await expect(rule('ingest_stale', [999])).rejects.toMatchObject({ code: 'invalid', field: 'channels' })
    })
  })
})
