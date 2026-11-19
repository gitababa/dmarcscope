// GET /domains/{domain}/export?range=30d&dataset=sources|timeseries: the page's
// data as CSV, for a signed-in person, limited to the domains they may see
// (a domain outside their scope answers 404, like a page would).

import type { NextRequest } from 'next/server'
import { getAccessWithRole } from '@/lib/auth/server'
import { parseRange } from '@/lib/format'
import { csvResponse, sourcesDataset, timeseriesDataset, toCsv, pathDomain } from '@/lib/exports'

export const dynamic = 'force-dynamic'

const notFound = () => new Response('Not found\n', { status: 404, headers: { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store' } })

export async function GET(req: NextRequest, ctx: { params: Promise<{ domain: string }> }) {
  const access = await getAccessWithRole('viewer')
  if (!access) return notFound()
  const domain = pathDomain((await ctx.params).domain)
  // The same ranges the pages offer (7d, 30d, 90d, all).
  const days = parseRange(req.nextUrl.searchParams.get('range') ?? undefined)
  const dataset = req.nextUrl.searchParams.get('dataset') === 'timeseries' ? 'timeseries' : 'sources'
  const d = dataset === 'timeseries' ? await timeseriesDataset(access.domains, domain, days) : await sourcesDataset(access.domains, domain, days)
  if (!d) return notFound()
  return csvResponse(toCsv(d), `dmarcscope-${domain}-${dataset}`)
}
