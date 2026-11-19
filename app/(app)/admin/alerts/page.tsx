import type { Metadata } from 'next'
import Link from 'next/link'
import { SubmitButton } from '@/components/client'
import { Icon } from '@/components/icons'
import { EmptyState, Notice, PageHeader, Pill } from '@/components/ui'
import {
  CHANNEL_KINDS,
  type ChannelKind,
  RULE_KINDS,
  evaluatorState,
  listChannels,
  listDeliveries,
  listEvents,
  listRules,
} from '@/lib/alerts/admin'
import type { RuleKind } from '@/lib/alerts/evaluate'
import { requirePageRole } from '@/lib/auth/server'
import { getPool } from '@/lib/db'
import { relTime } from '@/lib/format'
import { configStore } from '@/lib/settings'
import {
  createChannelAction,
  createRuleAction,
  deleteChannelAction,
  deleteRuleAction,
  evaluateNowAction,
  testChannelAction,
  toggleRuleAction,
  updateChannelAction,
  updateRuleAction,
} from '../alerts-actions'

export const dynamic = 'force-dynamic'
export const metadata: Metadata = { title: 'Alerts' }

const ERRORS: Record<string, string> = {
  not_allowed: 'Only administrators can do that.',
  invalid: 'That value is not valid.',
  not_found: 'That no longer exists. This is the current state.',
  rate_limited: 'A test was sent a moment ago. Wait ten seconds and try again.',
}

const FIELDS: Record<string, string> = {
  name: 'Name (1 to 100 characters)',
  kind: 'Kind',
  domain: 'Domain (empty for every domain; not used by "ingest stale")',
  min_messages: 'Minimum messages (1 to 10 000 000)',
  window_days: 'Window in days (1 to 30)',
  threshold_pct: 'Threshold in percent (1 to 100)',
  quiet_minutes: 'Remind after (60 to 10080 minutes)',
  channels: 'Channels',
  recipients: 'Recipients (1 to 10 email addresses)',
  url: 'Address (a full https:// URL)',
  signing_secret: 'Signing secret (16 to 256 characters, no spaces; required with a new address)',
}

const DONE: Record<string, string> = {
  rule_created: 'Rule created. It is evaluated every five minutes.',
  rule_saved: 'Rule saved.',
  rule_enabled: 'Rule enabled.',
  rule_disabled: 'Rule disabled. Its open events stay until it is enabled again.',
  rule_deleted: 'Rule deleted.',
  channel_created: 'Channel created. Use "Send test" to check it.',
  channel_saved: 'Channel saved.',
  channel_deleted: 'Channel deleted.',
  tested: 'Test sent. The result is in the delivery history.',
  evaluated: 'Evaluated now.',
}

function Field({ id, label, value, hint, required, type = 'text', maxLength, placeholder }: { id: string; label: string; value?: string | number | null; hint?: string; required?: boolean; type?: 'text' | 'password'; maxLength?: number; placeholder?: string }) {
  return (
    <div className="field">
      <label htmlFor={id}>{label}</label>
      <input id={id} name={id} type={type} defaultValue={value == null ? '' : String(value)} required={required} maxLength={maxLength} placeholder={placeholder} autoComplete={type === 'password' ? 'new-password' : 'off'} spellCheck={false} aria-describedby={hint ? `${id}-hint` : undefined} />
      {hint && <div id={`${id}-hint`} className="field-hint">{hint}</div>}
    </div>
  )
}

type RuleRowT = Awaited<ReturnType<typeof listRules>>[number]
type ChannelRowT = Awaited<ReturnType<typeof listChannels>>[number]

function RuleForm({ rule, channels, kind }: { rule?: RuleRowT; channels: ChannelRowT[]; kind: RuleKind }) {
  const p = rule?.params ?? {}
  const needsVolume = kind === 'new_failing_source' || kind === 'compliance_drop'
  return (
    <form action={rule ? updateRuleAction : createRuleAction} className="form">
      {rule && <input type="hidden" name="id" value={rule.id} />}
      <input type="hidden" name="kind" value={kind} />
      <Notice tone="info" role="note">{RULE_KINDS[kind].help}</Notice>
      <Field id="name" label="Name" value={rule?.name ?? RULE_KINDS[kind].label} required maxLength={100} />
      {kind !== 'ingest_stale' && <Field id="domain" label="Domain" value={rule?.domain} maxLength={253} placeholder="every domain" hint="Leave empty to watch every domain." />}
      {needsVolume && <Field id="min_messages" label="Minimum messages" value={p.min_messages ?? 100} maxLength={8} hint="Fewer messages than this give no verdict." />}
      {kind === 'compliance_drop' && <Field id="threshold_pct" label="Alert when compliance is below (%)" value={p.threshold_pct ?? 95} maxLength={3} />}
      {needsVolume && <Field id="window_days" label="Look back (days)" value={p.window_days ?? 7} maxLength={2} />}
      <Field id="quiet_minutes" label="Remind after (minutes)" value={rule?.quiet_minutes ?? 1440} maxLength={5} hint="An event is sent once; if it is still open after this long it is sent again, at most three times." />
      <fieldset className="field">
        <legend>Send to</legend>
        {channels.length === 0 && <div className="muted small">No channels yet. Add one below first.</div>}
        {channels.map((c) => (
          <label className="small" key={c.id} style={{ display: 'block' }}>
            <input type="checkbox" name="channels" value={c.id} defaultChecked={rule?.channel_ids.includes(c.id)} /> {c.name} <span className="muted">({CHANNEL_KINDS[c.kind].label.split(' (')[0]})</span>
          </label>
        ))}
      </fieldset>
      <label className="small"><input type="checkbox" name="notify_resolved" value="1" defaultChecked={rule?.notify_resolved} /> Also tell me when it clears</label>
      <label className="small"><input type="checkbox" name="enabled" value="1" defaultChecked={rule ? rule.enabled : true} /> Enabled</label>
      <div className="inline-form">
        <SubmitButton className="btn btn-primary btn-sm" pendingLabel="Saving…">{rule ? 'Save' : 'Add rule'}</SubmitButton>
        <Link href="/admin/alerts" className="small">Cancel</Link>
      </div>
    </form>
  )
}

function ChannelForm({ channel, kind }: { channel?: ChannelRowT; kind: ChannelKind }) {
  return (
    <form action={channel ? updateChannelAction : createChannelAction} className="form">
      {channel && <input type="hidden" name="id" value={channel.id} />}
      <input type="hidden" name="kind" value={kind} />
      <Field id="name" label="Name" value={channel?.name ?? CHANNEL_KINDS[kind].label.split(' (')[0]} required maxLength={100} />
      {kind === 'email' ? (
        <div className="field">
          <label htmlFor="recipients">Recipients</label>
          <textarea id="recipients" name="recipients" rows={3} required defaultValue={channel?.recipients.join('\n')} spellCheck={false} aria-describedby="recipients-hint" />
          <div id="recipients-hint" className="field-hint">One address per line, up to ten. Sent through the SMTP server in Settings.</div>
        </div>
      ) : (
        <>
          <Field
            id="url"
            label={kind === 'slack' ? 'Incoming webhook URL' : 'Webhook URL'}
            type="password"
            required={!channel}
            placeholder={channel?.secret_set ? `set (${channel.host}); type to replace` : 'https://…'}
            hint="Stored encrypted and never shown again. Replacing it needs the signing secret again for a signed webhook."
            maxLength={2000}
          />
          {kind === 'webhook' && <Field id="signing_secret" label="Signing secret" type="password" required={!channel} placeholder={channel?.secret_set ? 'set; type to replace (with the address)' : 'at least 16 characters, for example: openssl rand -hex 32'} hint="Requests carry an HMAC-SHA256 signature made with it. See docs/alerts.md for how to verify it." maxLength={256} />}
        </>
      )}
      <label className="small"><input type="checkbox" name="enabled" value="1" defaultChecked={channel ? channel.enabled : true} /> Enabled</label>
      <div className="inline-form">
        <SubmitButton className="btn btn-primary btn-sm" pendingLabel="Saving…">{channel ? 'Save' : 'Add channel'}</SubmitButton>
        <Link href="/admin/alerts" className="small">Cancel</Link>
      </div>
    </form>
  )
}

type Tab = 'events' | 'rules' | 'channels' | 'history'
const isTab = (v: unknown): v is Tab => v === 'events' || v === 'rules' || v === 'channels' || v === 'history'

const isRuleKind = (v: unknown): v is RuleKind => typeof v === 'string' && v in RULE_KINDS
const isChannelKind = (v: unknown): v is ChannelKind => typeof v === 'string' && v in CHANNEL_KINDS

export default async function AdminAlertsPage({
  searchParams,
}: {
  searchParams: Promise<{ error?: string; field?: string; done?: string; new?: string; rule?: string; channel?: string; newchannel?: string; confirm?: string; tab?: string }>
}) {
  const access = await requirePageRole('admin')
  const q = await searchParams
  const db = getPool()
  const [rules, channels, events, deliveries, evaluator, smtpHost] = await Promise.all([
    listRules(db),
    listChannels(db),
    listEvents(db),
    listDeliveries(db),
    evaluatorState(db),
    configStore().get('smtp.host').catch(() => null),
  ])
  const editRule = rules.find((r) => String(r.id) === q.rule)
  const editChannel = channels.find((c) => String(c.id) === q.channel)
  const newRuleKind = isRuleKind(q.new) ? q.new : null
  const newChannelKind = isChannelKind(q.newchannel) ? q.newchannel : null
  const hasEmail = channels.some((c) => c.kind === 'email')
  const openEvents = events.filter((e) => e.state === 'open').length
  const failedDeliveries = deliveries.filter((d) => d.status === 'failed').length
  // The tab follows what the page was asked to show, so the actions' redirects
  // (?rule=, ?newchannel=, ?done=…) land on the right one.
  const tab: Tab = isTab(q.tab)
    ? q.tab
    : q.rule || q.new || q.done?.startsWith('rule_')
      ? 'rules'
      : q.channel || q.newchannel || q.done?.startsWith('channel_')
        ? 'channels'
        : q.done === 'tested'
          ? 'history'
          : 'events'
  const TABS: Array<{ key: Tab; label: string; count?: number; bad?: boolean }> = [
    { key: 'events', label: 'Events', count: openEvents, bad: openEvents > 0 },
    { key: 'rules', label: 'Rules', count: rules.length },
    { key: 'channels', label: 'Channels', count: channels.length },
    { key: 'history', label: 'Delivery history', count: failedDeliveries || undefined, bad: failedDeliveries > 0 },
  ]

  return (
    <>
      <PageHeader title="Alerts" lead="Get told when something needs attention: a new source failing DMARC, compliance dropping, ingest stalling, or a published record changing." />

      {q.error && (
        <Notice tone="bad" role="alert">
          {ERRORS[q.error] ?? 'That could not be done.'}
          {q.error === 'invalid' && q.field && FIELDS[q.field] ? ` Check: ${FIELDS[q.field]}.` : ''}
        </Notice>
      )}
      {q.done && !q.error && DONE[q.done] && <Notice tone="ok" role="status">{DONE[q.done]}</Notice>}
      {hasEmail && !smtpHost && (
        <Notice tone="warn" role="note">An email channel exists but no SMTP server is set. The owner can set one in <Link href="/admin">Settings</Link>.</Notice>
      )}

      <nav className="tabs" aria-label="Alerts">
        {TABS.map((t) => (
          <a key={t.key} href={`/admin/alerts?tab=${t.key}`} aria-current={tab === t.key ? 'page' : undefined}>
            {t.label}
            {t.count != null && t.count > 0 && <span className={`count${t.bad ? ' bad' : ''}`}>{t.count}</span>}
          </a>
        ))}
      </nav>

      {tab === 'events' && (
      <>
      <section aria-labelledby="state-head">
        <div className="section-head"><h2 id="state-head">Evaluation</h2></div>
        <div className="card">
          <p className="small" style={{ margin: 0 }}>
            {evaluator.last_finished_at ? `Last evaluated ${relTime(evaluator.last_finished_at)}.` : 'Not evaluated yet.'} Rules are evaluated every five minutes by the web app (or by /api/cron/alerts on a serverless deployment).
            {evaluator.last_error && <span className="tone-bad"> {evaluator.last_error}.</span>}
          </p>
          <form action={evaluateNowAction} style={{ marginTop: '0.6rem' }}>
            <SubmitButton className="btn btn-sm" pendingLabel="Evaluating…">Evaluate now</SubmitButton>
          </form>
        </div>
      </section>

      <section className="section" aria-labelledby="events-head">
        <div className="section-head"><h2 id="events-head">Events</h2></div>
        <div className="card flush" role="list" aria-label="Alert events">
          {events.length === 0 && <div className="person-row muted">Nothing has fired yet.</div>}
          {events.map((e) => (
            <div className="person-row" role="listitem" key={e.id}>
              <div className="person-who">
                <div className="source-name">{e.summary}</div>
                <div className="source-meta">{e.rule_name} · first seen {relTime(e.first_seen_at)}{e.resolved_at ? ` · cleared ${relTime(e.resolved_at)}` : ''}</div>
              </div>
              <div className="person-tags"><Pill tone={e.state === 'open' ? 'bad' : 'ok'}>{e.state === 'open' ? 'Open' : 'Cleared'}</Pill></div>
            </div>
          ))}
        </div>
      </section>
      </>
      )}

      {tab === 'rules' && (
      <section aria-labelledby="rules-head">
        <div className="section-head"><h2 id="rules-head">Rules</h2></div>
        <div className="card flush" role="list" aria-label="Alert rules">
          {rules.length === 0 && <div className="person-row muted">None yet. Nothing is sent until you add a rule and a channel.</div>}
          {rules.map((r) => (
            <div className="person-row" role="listitem" key={r.id}>
              <div className="person-who">
                <div className="source-name"><Link href={`/admin/alerts?rule=${r.id}#rule-edit`}>{r.name}</Link></div>
                <div className="source-meta">{RULE_KINDS[r.kind].label}{r.domain ? ` · ${r.domain}` : ''} · {r.channel_ids.length} channel(s)</div>
                <div className="source-meta">{r.last_evaluated_at ? `Evaluated ${relTime(r.last_evaluated_at)}` : 'Not evaluated yet'}</div>
                {r.last_error && <div className="tone-bad small">{r.last_error}</div>}
              </div>
              <div className="person-tags">
                {r.open_events > 0 && <Pill tone="bad">{r.open_events} open</Pill>}
                <Pill tone={r.enabled ? 'ok' : 'muted'}>{r.enabled ? 'On' : 'Off'}</Pill>
                <form action={toggleRuleAction}>
                  <input type="hidden" name="id" value={r.id} />
                  <input type="hidden" name="enabled" value={r.enabled ? '0' : '1'} />
                  <SubmitButton className="btn btn-sm" pendingLabel="…">{r.enabled ? 'Turn off' : 'Turn on'}</SubmitButton>
                </form>
              </div>
            </div>
          ))}
        </div>
        <div id="rule-edit" className="card" style={{ marginTop: '0.8rem' }}>
          {editRule ? (
            <>
              <h3>Edit rule</h3>
              <RuleForm rule={editRule} channels={channels} kind={editRule.kind} />
              <form action={deleteRuleAction} className="inline-form" style={{ marginTop: '0.8rem' }}>
                <input type="hidden" name="id" value={editRule.id} />
                {q.confirm === 'delete' ? (
                  <>
                    <input type="hidden" name="confirm" value="yes" />
                    <span className="small">Delete this rule and its events?</span>
                    <SubmitButton className="btn btn-sm btn-danger" pendingLabel="Deleting…">Yes, delete</SubmitButton>
                  </>
                ) : (
                  <SubmitButton className="btn btn-sm" pendingLabel="…">Delete rule</SubmitButton>
                )}
              </form>
            </>
          ) : newRuleKind ? (
            <RuleForm channels={channels} kind={newRuleKind} />
          ) : (
            <nav className="inline-form" aria-label="Add a rule">
              <span className="small">Add a rule:</span>
              {(Object.keys(RULE_KINDS) as RuleKind[]).map((k) => (
                <Link key={k} href={`/admin/alerts?new=${k}#rule-edit`} className="btn btn-sm">{RULE_KINDS[k].label}</Link>
              ))}
            </nav>
          )}
        </div>
      </section>
      )}

      {tab === 'channels' && (
      <section aria-labelledby="channels-head">
        <div className="section-head"><h2 id="channels-head">Channels</h2></div>
        <div className="card flush" role="list" aria-label="Alert channels">
          {channels.length === 0 && <div className="person-row muted">None yet.</div>}
          {channels.map((c) => (
            <div className="person-row" role="listitem" key={c.id}>
              <div className="person-who">
                <div className="source-name"><Link href={`/admin/alerts?channel=${c.id}#channel-edit`}>{c.name}</Link></div>
                <div className="source-meta">
                  {CHANNEL_KINDS[c.kind].label.split(' (')[0]} · {c.kind === 'email' ? `${c.recipients.length} recipient(s)` : c.host ?? 'address set'}
                </div>
                {c.last_delivery && (
                  <div className={`source-meta${c.last_delivery.status === 'failed' ? ' tone-bad' : ''}`}>
                    Last {c.last_delivery.kind}: {c.last_delivery.status} {relTime(c.last_delivery.created_at)}{c.last_delivery.error ? ` (${c.last_delivery.error})` : ''}
                  </div>
                )}
              </div>
              <div className="person-tags">
                <Pill tone={c.enabled ? 'ok' : 'muted'}>{c.enabled ? 'On' : 'Off'}</Pill>
                <form action={testChannelAction}>
                  <input type="hidden" name="id" value={c.id} />
                  <SubmitButton className="btn btn-sm" pendingLabel="Sending…">Send test</SubmitButton>
                </form>
              </div>
            </div>
          ))}
        </div>
        <div id="channel-edit" className="card" style={{ marginTop: '0.8rem' }}>
          {editChannel ? (
            <>
              <h3>Edit channel</h3>
              <ChannelForm channel={editChannel} kind={editChannel.kind} />
              <form action={deleteChannelAction} className="inline-form" style={{ marginTop: '0.8rem' }}>
                <input type="hidden" name="id" value={editChannel.id} />
                {q.confirm === 'delete' ? (
                  <>
                    <input type="hidden" name="confirm" value="yes" />
                    <span className="small">Delete this channel? Rules lose it.</span>
                    <SubmitButton className="btn btn-sm btn-danger" pendingLabel="Deleting…">Yes, delete</SubmitButton>
                  </>
                ) : (
                  <SubmitButton className="btn btn-sm" pendingLabel="…">Delete channel</SubmitButton>
                )}
              </form>
            </>
          ) : newChannelKind ? (
            <ChannelForm kind={newChannelKind} />
          ) : (
            <nav className="inline-form" aria-label="Add a channel">
              <span className="small">Add a channel:</span>
              {(Object.keys(CHANNEL_KINDS) as ChannelKind[]).map((k) => (
                <Link key={k} href={`/admin/alerts?newchannel=${k}#channel-edit`} className="btn btn-sm">{CHANNEL_KINDS[k].label.split(' (')[0]}</Link>
              ))}
            </nav>
          )}
        </div>
      </section>
      )}

      {tab === 'history' && (
      <section aria-labelledby="history-head">
        <div className="section-head"><h2 id="history-head">Delivery history</h2></div>
        <div className="card flush" role="list" aria-label="Deliveries">
          {deliveries.length === 0 && <div className="person-row muted">Nothing sent yet.</div>}
          {deliveries.map((d) => (
            <div className="person-row" role="listitem" key={d.id}>
              <div className="person-who">
                <div className="source-name">{d.channel_name} · {d.kind}</div>
                <div className="source-meta">{relTime(d.created_at)} · {d.attempts} attempt(s)</div>
                {d.error && <div className="tone-bad small">{d.error}</div>}
              </div>
              <div className="person-tags"><Pill tone={d.status === 'sent' ? 'ok' : d.status === 'failed' ? 'bad' : 'warn'}>{d.status === 'queued' ? 'waiting' : d.status}</Pill></div>
            </div>
          ))}
        </div>
      </section>
      )}

    </>
  )
}
