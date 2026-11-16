import type { Metadata } from 'next'
import Link from 'next/link'
import { AUDIT_PAGE, listAudit } from '@/lib/admin'
import { requirePageRole } from '@/lib/auth/server'
import { fmtDate } from '@/lib/format'
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
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>When</th>
                <th>Who</th>
                <th>What</th>
                <th>Details</th>
              </tr>
            </thead>
            <tbody>
              {rows.length === 0 && (
                <tr>
                  <td colSpan={4} className="muted">
                    Nothing recorded yet.
                  </td>
                </tr>
              )}
              {rows.map((r) => (
                <tr key={r.id}>
                  <td className="muted" style={{ whiteSpace: 'nowrap' }}>
                    {fmtDate(r.at)} {new Date(r.at).toISOString().slice(11, 19)}
                  </td>
                  <td className="wrap">
                    {r.actor_email ?? <span className="muted">system</span>}
                    {r.ip && <div className="source-meta">{r.ip}</div>}
                  </td>
                  <td>
                    <code>{r.action}</code>
                    {r.target && <div className="source-meta">{r.target}</div>}
                  </td>
                  <td className="wrap source-meta">{describe(r.detail)}</td>
                </tr>
              ))}
            </tbody>
          </table>
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
