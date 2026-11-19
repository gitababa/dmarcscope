import type { Metadata } from 'next'
import Link from 'next/link'
import { notFound } from 'next/navigation'
import { AutoRefresh, FocusedSubmitButton, SubmitButton } from '@/components/client'
import { Icon } from '@/components/icons'
import { Card, Notice, PageHeader, Pill } from '@/components/ui'
import { requirePageRole } from '@/lib/auth/server'
import { getPool } from '@/lib/db'
import { fmtDate, relTime, untilTime } from '@/lib/format'
import { KINDS, type JobRow, type RunRow, getMailbox, isKind, listJobs, listRuns, shortError, workerStatus } from '@/lib/mail'
import { deleteMailboxAction, requestRunAction, requestTestAction, toggleMailboxAction } from '../../mail-actions'
import { MAIL_ERRORS, MAIL_FIELDS, MailboxForm, WorkerNotice, runState } from '../form'

export const dynamic = 'force-dynamic'
export const metadata: Metadata = { title: 'Mailbox' }

const DONE: Record<string, string> = {
  created: 'Mailbox added. Test the connection to check the settings; the worker reads it on its schedule.',
  saved: 'Saved. The worker uses the new settings from its next run.',
  queued: 'Asked the worker. The result appears below when it is done.',
  enabled: 'The mailbox is checked on schedule again.',
  disabled: 'Paused: the mailbox is no longer checked on schedule. Run now still works.',
}

const MAX_ERRORS_SHOWN = 20

function JobLine({ j }: { j: JobRow }) {
  const what = j.kind === 'test' ? 'Connection test' : 'Run now'
  const waiting = j.status === 'queued' || j.status === 'running'
  return (
    <div className="person-row" role="listitem">
      <div className="person-who">
        <div className="source-name">
          {what} <span className="muted small">{relTime(j.requested_at)}{j.requested_by_email ? ` by ${j.requested_by_email}` : ''}</span>
        </div>
        {j.result?.message && <div className={`small ${j.status === 'failed' ? 'tone-bad' : ''}`}>{shortError({ message: j.result.message }, 400)}</div>}
      </div>
      <div className="person-tags">
        {waiting ? (
          <Pill tone="info">{j.status === 'queued' ? 'waiting for the worker' : 'in progress'}</Pill>
        ) : (
          <Pill tone={j.status === 'done' ? 'ok' : 'bad'}>{j.status === 'done' ? 'succeeded' : 'failed'}</Pill>
        )}
      </div>
    </div>
  )
}

function RunLine({ r }: { r: RunRow }) {
  const errors = Array.isArray(r.errors) ? r.errors : []
  const running = !r.finished_at
  return (
    <div className="person-row" role="listitem">
      <div className="person-who">
        <div className="source-name">
          {fmtDate(r.started_at)} <span className="muted small">{relTime(r.started_at)} · {r.trigger === 'manual' ? 'run now' : 'scheduled'}</span>
        </div>
        <div className="source-meta">
          {r.messages_fetched} message(s) read, {r.reports_parsed} new report(s), {r.reports_skipped} set aside (duplicates, other domains, not reports)
          {errors.length ? `, ${errors.length} problem(s)` : ''}
        </div>
        {errors.length > 0 && (
          <details>
            <summary className="small">Problems</summary>
            <ul className="small" style={{ margin: '0.3rem 0 0', paddingLeft: '1.1rem', overflowWrap: 'anywhere' }}>
              {errors.slice(0, MAX_ERRORS_SHOWN).map((e, i) => (
                <li key={i}>{shortError(e)}</li>
              ))}
              {errors.length > MAX_ERRORS_SHOWN && <li className="muted">and {errors.length - MAX_ERRORS_SHOWN} more</li>}
            </ul>
          </details>
        )}
      </div>
      <div className="person-tags">
        {running ? <Pill tone="info" dot>running</Pill> : r.failed ? <Pill tone="bad" dot>failed</Pill> : <Pill tone="ok" dot>ok</Pill>}
      </div>
    </div>
  )
}

export default async function MailboxPage({
  params,
  searchParams,
}: {
  params: Promise<{ id: string }>
  searchParams: Promise<{ error?: string; field?: string; done?: string; confirm?: string; kind?: string }>
}) {
  const access = await requirePageRole('admin')
  const { id: rawId } = await params
  const { error, field, done, confirm, kind: switchTo } = await searchParams
  if (!/^\d{1,15}$/.test(rawId)) notFound()
  const id = Number(rawId)
  const db = getPool()
  const [mailbox, worker] = await Promise.all([getMailbox(db, id), workerStatus(db)])
  if (!mailbox) notFound()
  const [runs, jobs] = await Promise.all([listRuns(db, id, 30), listJobs(db, id, 6)])
  const waiting = jobs.some((j) => j.status === 'queued' || j.status === 'running') || runs.some((r) => !r.finished_at)
  const formKind = isKind(switchTo) ? switchTo : mailbox.kind
  const s = runState(mailbox)

  return (
    <>
      <AutoRefresh active={waiting} />
      <PageHeader
        crumbs={[{ href: '/admin/mail', label: 'Mailboxes' }, { label: mailbox.name }]}
        title={mailbox.name}
        badge={
          <Pill tone={s.tone} dot>
            {s.label}
          </Pill>
        }
        lead={
          <>
            {mailbox.username} · {KINDS[mailbox.kind].label}
          </>
        }
        actions={
          <>
            <form action={requestTestAction}>
              <input type="hidden" name="id" value={mailbox.id} />
              <SubmitButton className="btn btn-sm" pendingLabel="Asking…">
                <Icon name="zap" size={14} /> Test connection
              </SubmitButton>
            </form>
            <form action={requestRunAction}>
              <input type="hidden" name="id" value={mailbox.id} />
              <SubmitButton className="btn btn-sm btn-primary" pendingLabel="Asking…">
                <Icon name="refresh" size={14} /> Run now
              </SubmitButton>
            </form>
          </>
        }
      />

      {error && (
        <Notice tone="bad" role="alert">
          {MAIL_ERRORS[error] ?? 'That could not be done.'}
          {error === 'invalid' && field && MAIL_FIELDS[field] ? ` Check: ${MAIL_FIELDS[field]}.` : ''}
        </Notice>
      )}
      {done && !error && DONE[done] && (
        <Notice tone="ok" role="status">
          {DONE[done]}
        </Notice>
      )}

      <section className="section" aria-labelledby="state-head">
        <div className="card">
          <div className="card-head">
            <h2 id="state-head">
              <Icon name="inbox" size={16} /> Connection
            </h2>
          </div>
          <dl className="kv-list">
            <dt>Mailbox</dt>
            <dd>{mailbox.username}</dd>
            <dt>Kind</dt>
            <dd>
              {KINDS[mailbox.kind].label}
              {!KINDS[mailbox.kind].verified && <span className="muted small"> · not yet verified against the real provider</span>}
            </dd>
            <dt>Server</dt>
            <dd>
              {mailbox.host}:{mailbox.port} ({mailbox.security === 'ssl' ? 'TLS' : 'STARTTLS'})
            </dd>
            <dt>Schedule</dt>
            <dd>
              {mailbox.enabled ? `every ${mailbox.interval_minutes} minutes` : 'paused'}
              {mailbox.enabled && mailbox.next_run_at
                ? ` · next ${new Date(mailbox.next_run_at).getTime() <= Date.now() ? 'when a worker is free' : untilTime(mailbox.next_run_at)}`
                : ''}
            </dd>
            <dt>{KINDS[mailbox.kind].secretLabel}</dt>
            <dd>{mailbox.secret_set ? `set${mailbox.secret_updated_at ? `, last changed ${relTime(mailbox.secret_updated_at)}` : ''}` : 'not set'}</dd>
          </dl>
          <WorkerNotice alive={worker.alive} lastSeen={worker.lastSeen} />
          <div className="inline-form" style={{ marginTop: '0.8rem' }}>
            <form action={toggleMailboxAction}>
              <input type="hidden" name="id" value={mailbox.id} />
              <input type="hidden" name="enabled" value={mailbox.enabled ? '0' : '1'} />
              <SubmitButton className="btn btn-sm">{mailbox.enabled ? 'Pause schedule' : 'Resume schedule'}</SubmitButton>
            </form>
          </div>
        </div>
      </section>

      {jobs.length > 0 && (
        <section className="section" aria-labelledby="jobs-head" aria-live="polite">
          <div className="section-head">
            <h2 id="jobs-head">Requests</h2>
          </div>
          <div className="card flush" role="list" aria-label="Recent requests to the worker">
            {jobs.map((j) => (
              <JobLine key={j.id} j={j} />
            ))}
          </div>
        </section>
      )}

      <section className="section" aria-labelledby="runs-head">
        <div className="section-head">
          <h2 id="runs-head">Run history</h2>
        </div>
        <div className="card flush" role="list" aria-label="Runs of this mailbox">
          {runs.length === 0 && <div className="person-row muted">No runs yet.</div>}
          {runs.map((r) => (
            <RunLine key={r.id} r={r} />
          ))}
        </div>
        <p className="muted small">Problems quote the messages they are about, which anyone can send; they are shortened and shown as plain text.</p>
      </section>

      <section className="section" aria-labelledby="edit-head">
        <div className="section-head">
          <h2 id="edit-head">Settings</h2>
        </div>
        <div className="card">
          <nav className="inline-form small" aria-label="Kind of mailbox" style={{ marginBottom: '0.6rem' }}>
            <span className="muted">Kind:</span>
            {(Object.keys(KINDS) as Array<keyof typeof KINDS>).map((k) =>
              k === formKind ? (
                <strong key={k} aria-current="true">
                  {KINDS[k].label}
                </strong>
              ) : (
                <Link key={k} href={`/admin/mail/${mailbox.id}?kind=${k}#edit-head`}>
                  {KINDS[k].label}
                </Link>
              )
            )}
          </nav>
          {formKind !== mailbox.kind && (
            <Notice tone="warn" role="note">Changing the kind needs a new secret: the saved one belongs to the current kind.</Notice>
          )}
          <MailboxForm kind={formKind} mailbox={mailbox} />
        </div>
      </section>

      <section className="section" aria-labelledby="delete-head">
        <div className="card danger-zone">
          <div className="card-head">
            <h2 id="delete-head">
              <Icon name="trash" size={16} /> Delete this mailbox
            </h2>
          </div>
          {confirm === 'delete' ? (
            <form action={deleteMailboxAction} className="notice bad confirm" role="alert">
              <input type="hidden" name="id" value={mailbox.id} />
              <input type="hidden" name="confirm" value="yes" />
              <span>Delete this mailbox and its saved secret? Reports already read stay.</span>
              <span className="inline-form">
                <FocusedSubmitButton className="btn btn-sm btn-danger">Yes, delete</FocusedSubmitButton>
                <a href={`/admin/mail/${mailbox.id}`} className="small">
                  Cancel
                </a>
              </span>
            </form>
          ) : (
            <form action={deleteMailboxAction}>
              <input type="hidden" name="id" value={mailbox.id} />
              <SubmitButton className="btn btn-sm btn-danger-ghost">Delete…</SubmitButton>
            </form>
          )}
        </div>
      </section>
    </>
  )
}
