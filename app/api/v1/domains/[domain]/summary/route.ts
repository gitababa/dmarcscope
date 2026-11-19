import type { NextRequest } from 'next/server'
import { api, jsonError } from '@/lib/api-v1'
import { pathDomain } from '@/lib/exports'
import { getAlignmentBreakdown, getDomainPolicy } from '@/lib/queries'

export const dynamic = 'force-dynamic'

// GET /api/v1/domains/{domain}/summary?days=7: published policy and the
// alignment breakdown. Scope: domains:read. A domain outside the token's
// scope answers 404, as one that does not exist.
export const GET = (req: NextRequest, ctx: { params: Promise<{ domain: string }> }) =>
  api(req, 'domains:read', async ({ auth, days }) => {
    const domain = pathDomain((await ctx.params).domain)
    const policy = await getDomainPolicy(auth.domains, domain)
    if (!policy) return jsonError(404, 'not_found', 'No such domain.')
    const alignment = await getAlignmentBreakdown(auth.domains, domain, days)
    return Response.json({ data: { policy, alignment, days } }, { headers: { 'cache-control': 'no-store' } })
  })
