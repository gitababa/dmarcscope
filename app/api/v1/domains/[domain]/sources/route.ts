import type { NextRequest } from 'next/server'
import { api, dataResponse } from '@/lib/api-v1'
import { sourcesDataset, pathDomain } from '@/lib/exports'

export const dynamic = 'force-dynamic'

// GET /api/v1/domains/{domain}/sources?days=7[&format=csv]. Scope: reports:read.
export const GET = (req: NextRequest, ctx: { params: Promise<{ domain: string }> }) =>
  api(req, 'reports:read', async ({ auth, days }) => {
    const domain = pathDomain((await ctx.params).domain)
    return dataResponse(req, await sourcesDataset(auth.domains, domain, days), `dmarcscope-${domain}-sources`)
  })
