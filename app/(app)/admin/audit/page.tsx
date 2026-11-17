import type { Metadata } from 'next'
import Link from 'next/link'
import { AUDIT_PAGE, auditActions, listAudit, listPendingRequests, parseAuditFilters } from '@/lib/admin'
import { requirePageRole } from '@/lib/auth/server'
import { AdminNav } from '../nav'

export const dynamic = 'force-dynamic'
export const metadata: Metadata = { title: 'Audit log' }

// Detail values can come from a request (an address typed into a sign-in
// form): React escapes them, and they are shortened for display.
function describe(detail: Record<string, unknown>): string {
  const text = Object.entries(detail)
    .map(([k, v]) => `${k}=${typeof v === 'string' ? v : JSON.stringify(v)}`)
    .join(' ')
  return text.length > 300 ? `${text.slice(0, 300)}…` : text
}

type Search = { action?: string; actor?: string; target?: string; from?: string; to?: string; before?: string }

export default async function AdminAuditPage({ searchParams }: { searchParams: Promise<Search> }) {
  const access = await requirePageRole('admin')
  const params = await searchParams
  const filters = parseAuditFilters(params)
  const [rows, actions, pending] = await Promise.all([
    listAudit(access, filters, Number.parseInt(params.before || '', 10) || undefined),
    auditActions(access),
    listPendingRequests(access),
  ])
  const last = rows[rows.length - 1]
  const query = new URLSearchParams()
  for (const [k, v] of Object.entries(filters)) if (v) query.set(k, v)
  const filtered = query.size > 0
  const olderHref = (before: number) => {
    const q = new URLSearchParams(query)
    q.set('before', String(before))
    return `/admin/audit?${q}`
  }

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Administration</h1>
          <p>Sign-ins, refusals, setting changes, user changes and setup steps, newest first. Entries cannot be changed or deleted.</p>
        </div>
      </div>
      <AdminNav current="/admin/audit" pending={pending.length} />

      <form method="get" action="/admin/audit" className="filters" aria-label="Filter the audit log">
        <label htmlFor="a-action" className="visually-hidden">
          Action
        </label>
        <select id="a-action" name="action" defaultValue={filters.action ?? ''}>
          <option value="">Any action</option>
          {actions.map((a) => (
            <option key={a} value={a}>
              {a}
            </option>
          ))}
        </select>
        <label htmlFor="a-actor" className="visually-hidden">
          Who (address contains)
        </label>
        <input id="a-actor" name="actor" type="search" placeholder="Who" defaultValue={filters.actor} maxLength={320} />
        <label htmlFor="a-target" className="visually-hidden">
          Target contains
        </label>
        <input id="a-target" name="target" type="search" placeholder="Target (user:12, cron.secret…)" defaultValue={filters.target} maxLength={200} />
        <label htmlFor="a-from">From</label>
        <input id="a-from" name="from" type="date" defaultValue={filters.from} />
        <label htmlFor="a-to">to</label>
        <input id="a-to" name="to" type="date" defaultValue={filters.to} />
        <button className="btn btn-sm" type="submit">
          Filter
        </button>
        {filtered && (
          <Link href="/admin/audit" className="small">
            Clear
          </Link>
        )}
        <a className="btn btn-sm" href={`/admin/audit/export${filtered ? `?${query}` : ''}`} download>
          Download CSV
        </a>
      </form>

      <div className="card flush">
        <div role="list" aria-label="Audit log">
          {rows.length === 0 && <div className="audit-row muted">{filtered ? 'No entries match.' : 'Nothing recorded yet.'}</div>}
          {rows.map((r) => (
            <div className="audit-row" role="listitem" key={r.id}>
              <div className="muted small audit-when">{new Date(r.at).toISOString().replace('T', ' ').slice(0, 19)} UTC</div>
              <div className="audit-what">
                <code>{r.action}</code>
                {r.target && <span className="source-meta"> {r.target}</span>}
              </div>
              <div className="audit-who">
                {r.actor_email ?? <span className="muted">{r.ip ? 'not signed in' : 'system'}</span>}
                {r.ip && <span className="source-meta"> · {r.ip}</span>}
              </div>
              <div className="source-meta audit-detail">{describe(r.detail)}</div>
            </div>
          ))}
        </div>
        {rows.length === AUDIT_PAGE && last && (
          <div className="card-foot">
            <Link href={olderHref(last.id)}>Older entries →</Link>
          </div>
        )}
      </div>
    </>
  )
}
