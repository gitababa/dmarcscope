import type { Metadata } from 'next'
import Link from 'next/link'
import { AUDIT_PAGE, listAudit } from '@/lib/admin'
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

export default async function AdminAuditPage({ searchParams }: { searchParams: Promise<{ before?: string }> }) {
  const access = await requirePageRole('admin')
  const { before } = await searchParams
  const rows = await listAudit(access, Number.parseInt(before || '', 10) || undefined)
  const last = rows[rows.length - 1]

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Administration</h1>
          <p>Sign-ins, refusals, setting changes, user changes and setup steps, newest first. Entries cannot be changed or deleted.</p>
        </div>
      </div>
      <AdminNav current="/admin/audit" />
      <div className="card flush">
        <div role="list" aria-label="Audit log">
          {rows.length === 0 && <div className="audit-row muted">Nothing recorded yet.</div>}
          {rows.map((r) => (
            <div className="audit-row" role="listitem" key={r.id}>
              <div className="muted small audit-when">
                {new Date(r.at).toISOString().replace('T', ' ').slice(0, 19)} UTC
              </div>
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
            <Link href={`/admin/audit?before=${last.id}`}>Older entries →</Link>
          </div>
        )}
      </div>
    </>
  )
}
