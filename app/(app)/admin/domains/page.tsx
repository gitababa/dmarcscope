import type { Metadata } from 'next'
import { Card, Notice, PageHeader } from '@/components/ui'
import { SubmitButton } from '@/components/client'
import { requirePageRole } from '@/lib/auth/server'
import { getPool } from '@/lib/db'
import { domainsFromEnvironment, listDomains } from '@/lib/mail'
import { MAIL_ERRORS, MAIL_FIELDS } from '../mail/form'
import { addDomainAction, removeDomainAction } from '../mail-actions'

export const dynamic = 'force-dynamic'
export const metadata: Metadata = { title: 'Domains' }

const DONE: Record<string, string> = {
  added: 'Domain added. Reports about it are read from the next run on.',
  removed: 'Domain removed. New reports about it are ignored; reports already stored stay.',
}

export default async function AdminDomainsPage({ searchParams }: { searchParams: Promise<{ error?: string; field?: string; done?: string }> }) {
  const access = await requirePageRole('admin')
  const { error, field, done } = await searchParams
  const domains = await listDomains(getPool())
  const fromEnv = domainsFromEnvironment()

  return (
    <>
      <PageHeader title="Monitored domains" lead={<>The domains you monitor. Reports about any other domain are ignored: anyone can email a report to your mailbox,
            so this list decides what gets stored and shown.</>} />

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

      {fromEnv ? (
        <section className="section" aria-labelledby="env-domains-head">
          <div className="section-head">
            <h2 id="env-domains-head">Monitored domains</h2>
            <span className="muted small">managed by environment (ALLOWED_DOMAINS)</span>
          </div>
          <div className="card flush" role="list" aria-label="Monitored domains from ALLOWED_DOMAINS">
            {fromEnv.map((d) => (
              <div className="person-row" role="listitem" key={d}>
                <div className="person-who source-name">{d}</div>
              </div>
            ))}
          </div>
          <p className="muted small">
            To manage the list here instead, add these domains here first, then remove ALLOWED_DOMAINS from the web app&rsquo;s and
            the worker&rsquo;s environment.
            {domains.length > 0 ? ` ${domains.length} domain(s) saved here are ignored while it is set.` : ''}
          </p>
        </section>
      ) : (
        <>
          <section className="section" aria-labelledby="domains-head">
            <div className="section-head">
              <h2 id="domains-head">Monitored domains</h2>
            </div>
            <div className="card flush" role="list" aria-label="Monitored domains">
              {domains.length === 0 && (
                <div className="person-row muted">None yet. Mailboxes configured in the panel read nothing until you add one.</div>
              )}
              {domains.map((d) => (
                <div className="person-row" role="listitem" key={d.id}>
                  <div className="person-who">
                    <div className="source-name">{d.name}</div>
                    {d.created_by_email && <div className="source-meta">added by {d.created_by_email}</div>}
                  </div>
                  <form action={removeDomainAction}>
                    <input type="hidden" name="id" value={d.id} />
                    <SubmitButton className="btn btn-sm">
                      Remove<span className="visually-hidden"> {d.name}</span>
                    </SubmitButton>
                  </form>
                </div>
              ))}
            </div>
          </section>
          <section className="section" aria-labelledby="add-domain-head">
            <div className="section-head">
              <h2 id="add-domain-head">Add a domain</h2>
            </div>
            <div className="card">
              <form action={addDomainAction} className="inline-form">
                <label htmlFor="domain" className="visually-hidden">
                  Domain
                </label>
                <input id="domain" name="domain" required maxLength={253} placeholder="example.com" className="grow" autoComplete="off" spellCheck={false} />
                <SubmitButton className="btn btn-primary btn-sm">Add domain</SubmitButton>
              </form>
              <p className="muted small" style={{ marginBottom: 0 }}>
                Subdomains are separate: add each domain whose reports you want. Internationalised names in their xn-- form.
              </p>
            </div>
          </section>
        </>
      )}
    </>
  )
}
