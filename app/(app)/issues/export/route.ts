// GET /issues/export?range=30d[&domain=example.com]: the problem sources as CSV,
// limited to the domains the signed-in person may see.

import type { NextRequest } from 'next/server'
import { getAccessWithRole } from '@/lib/auth/server'
import { parseRange } from '@/lib/format'
import { csvResponse, problemsDataset, toCsv } from '@/lib/exports'

export const dynamic = 'force-dynamic'

export async function GET(req: NextRequest) {
  const access = await getAccessWithRole('viewer')
  if (!access) return new Response('Not found\n', { status: 404, headers: { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store' } })
  // The same ranges the pages offer (7d, 30d, 90d, all).
  const days = parseRange(req.nextUrl.searchParams.get('range') ?? undefined)
  const domain = req.nextUrl.searchParams.get('domain')?.toLowerCase() || undefined
  return csvResponse(toCsv(await problemsDataset(access.domains, days, domain)), 'dmarcscope-problems')
}
