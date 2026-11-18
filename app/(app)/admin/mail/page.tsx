import type { Metadata } from 'next'
import Link from 'next/link'
import { Pill } from '@/components/ui'
import { listPendingRequests } from '@/lib/admin'
import { requirePageRole } from '@/lib/auth/server'
import { getPool } from '@/lib/db'
import { relTime, untilTime } from '@/lib/format'
import { KINDS, domainsFromEnvironment, isKind, listDomains, listMailboxes, shortError, workerStatus } from '@/lib/mail'
import { AdminNav } from '../nav'
import { MAIL_ERRORS, MAIL_FIELDS, MailboxForm, WorkerNotice, runState } from './form'

export const dynamic = 'force-dynamic'
export const metadata: Metadata = { title: 'Mail' }

const DONE: Record<string, string> = {
  deleted: 'Mailbox deleted. The reports it brought in stay.',
}

export default async function AdminMailPage({ searchParams }: { searchParams: Promise<{ error?: string; field?: string; done?: string; new?: string }> }) {
  const access = await requirePageRole('admin')
  const { error, field, done, new: adding } = await searchParams
  const db = getPool()
  const [pending, mailboxes, worker, domains] = await Promise.all([listPendingRequests(access), listMailboxes(db), workerStatus(db), listDomains(db)])
  const envDomains = domainsFromEnvironment()
  const noDomains = !envDomains && domains.length === 0
  const newKind = isKind(adding) ? adding : null

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Administration</h1>
          <p>The mailboxes DMARC reports are read from. The worker checks each on its schedule; you can test one or run it now.</p>
        </div>
      </div>
      <AdminNav current="/admin/mail" pending={pending.length} />

      {error && (
        <div className="notice bad" role="alert">
          {MAIL_ERRORS[error] ?? 'That could not be done.'}
          {error === 'invalid' && field && MAIL_FIELDS[field] ? ` Check: ${MAIL_FIELDS[field]}.` : ''}
        </div>
      )}
      {done && !error && DONE[done] && (
        <div className="notice ok" role="status">
          {DONE[done]}
        </div>
      )}
      {noDomains && (
        <div className="notice warn" role="note">
          <span>
            No monitored domains yet: mailboxes saved here read nothing until you <Link href="/admin/domains">add the domains you monitor</Link>.
            Reports about any other domain are ignored.
          </span>
        </div>
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
          <WorkerNotice alive={0} lastSeen={worker.lastSeen} />
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
                    {m.enabled && m.next_run_at ? ` · next ${new Date(m.next_run_at).getTime() <= Date.now() ? 'when a worker is free' : untilTime(m.next_run_at)}` : ''}
                  </div>
                  {lastError && <div className="tone-bad small">{shortError(lastError, 160)}</div>}
                </div>
                <div className="person-tags">
                  <Pill tone={s.tone}>{s.label}</Pill>
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
            <nav className="inline-form" aria-label="Kind of mailbox">
              {(Object.keys(KINDS) as Array<keyof typeof KINDS>).map((k) => (
                <Link key={k} href={`/admin/mail?new=${k}#add-head`} className="btn btn-sm">
                  {KINDS[k].label}
                </Link>
              ))}
            </nav>
          )}
        </div>
      </section>
    </>
  )
}
