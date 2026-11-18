// Sends queued deliveries. A sender claims rows with FOR UPDATE SKIP LOCKED
// and a short lease, so replicas never send the same row twice; delivery is
// at-least-once (a send whose acknowledgement was lost may be repeated, which
// is why a webhook carries a stable event_id).
//
// This is the only place in the web app that decrypts purpose 'alert'.

import { createHmac } from 'node:crypto'
import type { Pool } from 'pg'
import { type Env } from '../config'
import { EnvelopeError, decryptSecret } from '../crypto'
import { configStore } from '../settings'
import { DestinationRefused, type Resolver, post, resolveDestination } from './net'
import { type AlertContent, type AlertFact, clean, renderEmail, renderSlack, renderWebhook } from './render'
import { type SmtpConfig, SmtpError, sendMail } from './smtp'

export const MAX_ATTEMPTS = 4
const RETRY_MINUTES = [1, 5, 30]
const LEASE_MINUTES = 2

export const channelContext = (id: number) => `alert:${id}`

type Claimed = { id: number; event_id: number | null; channel_id: number; kind: AlertContent['kind']; attempts: number }

type Overrides = {
  env?: Env
  resolve?: Resolver
  smtp?: () => Promise<SmtpConfig | null>
  smtpCa?: string
  appUrl?: string
  appName?: string
  allowPrivate?: boolean
}

class Permanent extends Error {}

async function smtpFromSettings(env: Env): Promise<SmtpConfig | null> {
  const s = configStore()
  const [host, port, security, username, password, from] = await Promise.all([
    s.get('smtp.host', env),
    s.get('smtp.port', env),
    s.get('smtp.security', env),
    s.get('smtp.username', env),
    s.readSecret('smtp.password', env),
    s.get('smtp.from', env),
  ])
  if (!host || !from) return null
  return { host: String(host), port: Number(port), security: security === 'ssl' ? 'ssl' : 'starttls', username: username ? String(username) : null, password, from: String(from) }
}

export async function deliverDue(pool: Pool, o: Overrides = {}): Promise<{ sent: number; failed: number; retried: number }> {
  const env = o.env ?? process.env
  const out = { sent: 0, failed: 0, retried: 0 }
  for (;;) {
    const { rows } = await pool.query<Claimed>(
      `UPDATE alert_deliveries SET attempts = attempts + 1, next_attempt_at = NOW() + make_interval(mins => $1::int)
        WHERE id IN (SELECT id FROM alert_deliveries WHERE status = 'queued' AND next_attempt_at <= NOW()
                      ORDER BY id LIMIT 10 FOR UPDATE SKIP LOCKED)
        RETURNING id::int AS id, event_id::int AS event_id, channel_id::int AS channel_id, kind, attempts`,
      [LEASE_MINUTES]
    )
    if (rows.length === 0) return out
    for (const d of rows) {
      try {
        await sendOne(pool, d, o, env)
        await pool.query(`UPDATE alert_deliveries SET status = 'sent', error = NULL, finished_at = NOW() WHERE id = $1`, [d.id])
        out.sent++
      } catch (err) {
        const permanent = err instanceof Permanent || err instanceof EnvelopeError
        const message = err instanceof EnvelopeError ? 'the saved secret cannot be decrypted (APP_SECRET changed?)' : clean(err instanceof Error ? err.message : err, 300)
        if (permanent || d.attempts >= MAX_ATTEMPTS) {
          await pool.query(`UPDATE alert_deliveries SET status = 'failed', error = $2, finished_at = NOW() WHERE id = $1`, [d.id, message])
          out.failed++
        } else {
          const wait = RETRY_MINUTES[Math.min(d.attempts - 1, RETRY_MINUTES.length - 1)]
          await pool.query(`UPDATE alert_deliveries SET error = $2, next_attempt_at = NOW() + make_interval(mins => $3::int) WHERE id = $1`, [d.id, message, wait])
          out.retried++
        }
      }
    }
  }
}

async function sendOne(pool: Pool, d: Claimed, o: Overrides, env: Env): Promise<void> {
  const ch = (
    await pool.query<{ kind: 'email' | 'webhook' | 'slack'; enabled: boolean; config: { recipients?: string[] }; secret: string | null }>(
      `SELECT kind, enabled, config, secret FROM alert_channels WHERE id = $1`,
      [d.channel_id]
    )
  ).rows[0]
  if (!ch || !ch.enabled) throw new Permanent('the channel is disabled or was deleted')

  let content: AlertContent
  if (d.event_id == null) {
    content = { kind: 'test', eventId: null, ruleName: 'Test notification', ruleKind: 'test', domain: null, summary: 'This is a test from DMARCscope. If you can read it, the channel works.', facts: [], link: null, at: new Date().toISOString() }
  } else {
    const ev = (
      await pool.query<{ state: string; summary: string; domain: string | null; detail: { facts?: AlertFact[] }; rule_name: string; rule_kind: string }>(
        `SELECT e.state, e.summary, e.domain, e.detail, r.name AS rule_name, r.kind AS rule_kind
           FROM alert_events e JOIN alert_rules r ON r.id = e.rule_id WHERE e.id = $1`,
        [d.event_id]
      )
    ).rows[0]
    if (!ev) throw new Permanent('the event no longer exists')
    if (ev.state === 'resolved' && d.kind !== 'resolved') throw new Permanent('cancelled: the condition cleared before this was sent')
    const base = (o.appUrl ?? env.APP_URL ?? '').replace(/\/+$/, '')
    content = {
      kind: d.kind,
      eventId: d.event_id,
      ruleName: ev.rule_name,
      ruleKind: ev.rule_kind,
      domain: ev.domain,
      summary: ev.summary,
      facts: ev.detail?.facts ?? [],
      link: base ? `${base}/admin/alerts` : null,
      at: new Date().toISOString(),
    }
  }
  const appName = o.appName ?? String((await configStore().get('app.name', env).catch(() => null)) ?? 'DMARCscope')

  if (ch.kind === 'email') {
    const cfg = await (o.smtp ? o.smtp() : smtpFromSettings(env))
    if (!cfg) throw new Permanent('SMTP is not configured (Admin → Settings)')
    const to = ch.config?.recipients ?? []
    const { subject, text } = renderEmail(content, appName)
    try {
      await sendMail(cfg, { to, subject, text }, { ca: o.smtpCa })
    } catch (e) {
      if (e instanceof SmtpError && /sender address|recipient list/.test(e.message)) throw new Permanent(e.message)
      throw e
    }
    return
  }

  if (!ch.secret) throw new Permanent('the channel has no address saved')
  const stored = JSON.parse(decryptSecret('alert', channelContext(d.channel_id), ch.secret, env).plaintext) as { url: string; signing_secret?: string }
  const allowPrivate = o.allowPrivate ?? (await configStore().get('alerts.allow_private_webhooks', env)) === true
  let dest
  try {
    dest = await resolveDestination(stored.url, { allowPrivate, resolve: o.resolve })
  } catch (e) {
    if (e instanceof DestinationRefused) throw new Error(`refused: ${e.message}`)
    throw e
  }
  let body: string
  const headers: Record<string, string> = { 'Content-Type': 'application/json' }
  if (ch.kind === 'slack') {
    body = JSON.stringify(renderSlack(content, appName))
  } else {
    body = JSON.stringify(renderWebhook(content))
    const ts = String(Math.floor(Date.now() / 1000))
    headers['X-DMARCscope-Timestamp'] = ts
    headers['X-DMARCscope-Event-Id'] = String(content.eventId ?? 'test')
    headers['X-DMARCscope-Signature'] = `v1=${createHmac('sha256', stored.signing_secret ?? '').update(`${ts}.${body}`).digest('hex')}`
  }
  const res = await post(dest, body, headers)
  if (res.status < 200 || res.status >= 300) throw new Error(`the receiver answered HTTP ${res.status}`)
}
