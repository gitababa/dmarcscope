import type { NextRequest } from 'next/server'
import { api, jsonError } from '@/lib/api-v1'
import { pathDomain } from '@/lib/exports'
import { getLatestDnsCheck } from '@/lib/queries'

export const dynamic = 'force-dynamic'

// GET /api/v1/domains/{domain}/dns: the latest DNS check. Scope: dns:read.
export const GET = (req: NextRequest, ctx: { params: Promise<{ domain: string }> }) =>
  api(req, 'dns:read', async ({ auth }) => {
    const domain = pathDomain((await ctx.params).domain)
    const results = await getLatestDnsCheck(auth.domains, domain)
    if (!results) return jsonError(404, 'not_found', 'No DNS check for this domain.')
    return Response.json({ data: results }, { headers: { 'cache-control': 'no-store' } })
  })
