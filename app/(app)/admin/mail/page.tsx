import type { Metadata } from 'next'
import { Icon } from '@/components/icons'
import Link from 'next/link'
import {Card,Notice,PageHeader,Pill } from '@/components/ui'
import { requirePageRole } from '@/lib/auth/server'
import { getPool } from '@/lib/db'
import { relTime, untilTime } from '@/lib/format'
import { KINDS, domainsFromEnvironment, isKind, listDomains, listMailboxes, passStatus, shortError, workerStatus } from '@/lib/mail'
import { MAIL_ERRORS, MAIL_FIELDS, MailboxForm, WorkerNotice, nextRunLabel, runState, scheduleWarning } from './form'

export const dynamic = 'force-dynamic'
export const metadata: Metadata = { title: 'Mailboxes' }

const KIND_BLURB: Record<string, string> = {
  imap: 'Any IMAP server, with a password or app password.',
  microsoft: 'Exchange Online through an app registration (OAuth).',
  google: 'Gmail through a service account with domain-wide delegation.',
}

const DONE: Record<string, string> = {
  deleted: 'Mailbox deleted. The reports it brought in stay.',
}

export default async function AdminMailPage({ searchParams }: { searchParams: Promise<{ error?: string; field?: string; done?: string; new?: string }> }) {
  const access = await requirePageRole('admin')
  const { error, field, done, new: adding } = await searchParams
  const db = getPool()
  const [mailboxes, worker, domains, passes] = await Promise.all([listMailboxes(db), workerStatus(db), listDomains(db), passStatus(db)])
  const envDomains = domainsFromEnvironment()
  const noDomains = !envDomains && domains.length === 0
  const newKind = isKind(adding) ? adding : null

  return (
    <>
      <PageHeader title="Mailboxes" lead="The mailboxes DMARC reports are read from. Each is read on its schedule; you can test one or run it now." />

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
      {noDomains && (
        <Notice tone="info" role="note">
          No monitored domains yet. Mailboxes are read, but nothing is stored: the domains found in reports are listed under{' '}
          <Link href="/admin/domains">Domains</Link>, and their reports are held for 14 days until you choose which to monitor.
        </Notice>
      )}

      <section className="section" aria-labelledby="mailboxes-head">
        <div className="section-head">
          <h2 id="mailboxes-head">Mailboxes</h2>
        </div>
        {worker.alive > 0 ? (
          <div className="card" style={{ marginBottom: '0.8rem' }}>
            <WorkerNotice alive={worker.alive} lastSeen={worker.lastSeen} />
          </div>
        ) : (
          <WorkerNotice alive={0} lastSeen={worker.lastSeen} passes={passes} />
        )}
        <div className="card flush" role="list" aria-label="Mailboxes">
          {mailboxes.length === 0 && (
            <div className="person-row muted">
              None yet.{process.env.IMAP_HOST ? ' A mailbox is also configured by environment variables (IMAP_HOST) for python -m ingestor run.' : ''}
            </div>
          )}
          {mailboxes.map((m) => {
            const s = runState(m)
            const lastError = m.last_run?.failed ? m.last_run.errors?.[m.last_run.errors.length - 1] : null
            return (
              <div className="person-row" role="listitem" key={m.id}>
                <span className={`row-icon ${s.tone === 'ok' ? 'ok' : s.tone === 'bad' ? 'bad' : s.tone === 'warn' ? 'warn' : ''}`}>
                  <Icon name="inbox" size={16} />
                </span>
                <div className="person-who">
                  <div className="source-name">
                    <Link href={`/admin/mail/${m.id}`}>{m.name}</Link>
                  </div>
                  <div className="source-meta">
                    {m.username} · {KINDS[m.kind].label}
                    {!KINDS[m.kind].verified ? ' (unverified)' : ''}
                  </div>
                  <div className="source-meta">
                    {m.last_run ? `Last run ${relTime(m.last_run.started_at)}` : 'Never run'}
                    {nextRunLabel(m, untilTime) ? ` · next ${nextRunLabel(m, untilTime)}` : ''}
                  </div>
                  {scheduleWarning(m, passes) && <div className="tone-warn small">{scheduleWarning(m, passes)}</div>}
                  {lastError && <div className="tone-bad small">{shortError(lastError, 160)}</div>}
                </div>
                <div className="person-tags">
                  <Pill tone={s.tone} dot>
                    {s.label}
                  </Pill>
                  <Link href={`/admin/mail/${m.id}`} className="btn btn-sm btn-ghost">
                    Open <Icon name="chevronRight" size={13} />
                  </Link>
                </div>
              </div>
            )
          })}
        </div>
      </section>

      <section className="section" aria-labelledby="add-head">
        <div className="section-head">
          <h2 id="add-head">Add a mailbox</h2>
        </div>
        <div className="card">
          {newKind ? (
            <MailboxForm kind={newKind} />
          ) : (
            <nav className="kind-picker" aria-label="Kind of mailbox">
              {(Object.keys(KINDS) as Array<keyof typeof KINDS>).map((k) => (
                <Link key={k} href={`/admin/mail?new=${k}#add-head`} className="kind-option">
                  <strong>
                    <Icon name={k === 'imap' ? 'server' : 'mail'} size={16} /> {KINDS[k].label}
                  </strong>
                  <span>{KIND_BLURB[k] ?? ''}</span>
                </Link>
              ))}
            </nav>
          )}
        </div>
      </section>
    </>
  )
}
