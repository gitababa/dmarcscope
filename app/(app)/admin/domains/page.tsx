import type { Metadata } from 'next'
import { Card, Notice, PageHeader, Pill } from '@/components/ui'
import { SubmitButton } from '@/components/client'
import { requirePageRole } from '@/lib/auth/server'
import { getPool } from '@/lib/db'
import { relTime } from '@/lib/format'
import { type FoundDomain, domainsFromEnvironment, listDomains, listFoundDomains } from '@/lib/mail'
import { MAIL_ERRORS, MAIL_FIELDS } from '../mail/form'
import { addDomainAction, removeDomainAction } from '../mail-actions'

export const dynamic = 'force-dynamic'
export const metadata: Metadata = { title: 'Domains' }

const DONE: Record<string, string> = {
  added: 'Domain added. Its reports are stored from now on, and any held for it are being imported.',
  removed: 'Domain removed. New reports about it are ignored; reports already stored stay.',
}

export default async function AdminDomainsPage({ searchParams }: { searchParams: Promise<{ error?: string; field?: string; done?: string }> }) {
  const access = await requirePageRole('admin')
  const { error, field, done } = await searchParams
  const [domains, found] = await Promise.all([listDomains(getPool()), listFoundDomains(getPool())])
  const fromEnv = domainsFromEnvironment()
  const groups = groupByBase(found)

  return (
    <>
      <PageHeader
        title="Domains"
        lead={
          <>
            The domains you monitor, and the others reports were about. Only monitored domains are stored and shown: anyone can email a
            report to your mailbox. Reports about other domains are held for 14 days, so monitoring one imports what came in meanwhile.
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

      <FoundDomains groups={groups} canMonitor={!fromEnv} />

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
                <div className="person-row muted">None yet. Until you add one, mailboxes are read but nothing is stored.</div>
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

type Group = { base: string; domains: FoundDomain[] }

// Subdomains under their registrable domain (public suffix list, worked out
// by the worker), the registrable domain itself first.
function groupByBase(found: FoundDomain[]): Group[] {
  const map = new Map<string, FoundDomain[]>()
  for (const d of found) {
    const base = d.base_domain || d.name
    map.set(base, [...(map.get(base) ?? []), d])
  }
  return [...map.entries()]
    .map(([base, list]) => ({ base, domains: list.sort((a, b) => (a.name === base ? -1 : b.name === base ? 1 : a.name.localeCompare(b.name))) }))
    .sort((a, b) => a.base.localeCompare(b.base))
}

function FoundDomains({ groups, canMonitor }: { groups: Group[]; canMonitor: boolean }) {
  return (
    <section className="section" aria-labelledby="found-head">
      <div className="section-head">
        <h2 id="found-head">Found in reports</h2>
        <span className="muted small">a subdomain has its own reports only if it publishes its own DMARC record</span>
      </div>
      <div className="card flush" role="list" aria-label="Domains found in reports">
        {groups.length === 0 && <div className="person-row muted">No reports have been read yet.</div>}
        {groups.map((g) =>
          g.domains.map((d) => (
            <div className="person-row" role="listitem" key={d.name}>
              <div className="person-who" style={d.name !== g.base ? { paddingLeft: '1.25rem' } : undefined}>
                <div className="source-name">{d.name}</div>
                <div className="source-meta">
                  {d.reports_seen} {d.reports_seen === 1 ? 'report' : 'reports'} · last {relTime(d.last_seen_at)}
                  {!d.monitored && d.held > 0 ? ` · ${d.held} held` : ''}
                </div>
              </div>
              <div className="person-tags">
                {d.monitored ? (
                  <Pill tone="ok" dot>
                    monitored
                  </Pill>
                ) : canMonitor ? (
                  <form action={addDomainAction}>
                    <input type="hidden" name="domain" value={d.name} />
                    <input type="hidden" name="back" value="/admin/domains" />
                    <SubmitButton className="btn btn-sm btn-primary">
                      Monitor<span className="visually-hidden"> {d.name}</span>
                    </SubmitButton>
                  </form>
                ) : (
                  <Pill tone="muted">not in ALLOWED_DOMAINS</Pill>
                )}
              </div>
            </div>
          ))
        )}
      </div>
    </section>
  )
}
