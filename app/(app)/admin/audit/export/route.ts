// GET /admin/audit/export?<filters>: the filtered audit log as CSV, for
// administrators. The request gate already requires a session; this checks
// the role itself, and records the export in the audit log.

import type { NextRequest } from 'next/server'
import { AUDIT_EXPORT_LIMIT, auditCsv, exportAudit, parseAuditFilters } from '@/lib/admin'
import { audit, getAccessWithRole } from '@/lib/auth/server'

export const dynamic = 'force-dynamic'

export async function GET(req: NextRequest) {
  const access = await getAccessWithRole('admin')
  if (!access) {
    await audit('action_refused', { action: 'audit_exported', reason: 'not_allowed' })
    return new Response('Not found\n', { status: 404, headers: { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store' } })
  }
  const filters = parseAuditFilters(Object.fromEntries(req.nextUrl.searchParams))
  const rows = await exportAudit(access, filters)
  await audit('audit_exported', { rows: rows.length, truncated: rows.length >= AUDIT_EXPORT_LIMIT, filters })
  const stamp = new Date().toISOString().slice(0, 10)
  return new Response(auditCsv(rows), {
    headers: {
      'content-type': 'text/csv; charset=utf-8',
      'content-disposition': `attachment; filename="dmarcscope-audit-${stamp}.csv"`,
      'cache-control': 'no-store',
      'x-content-type-options': 'nosniff',
    },
  })
}
