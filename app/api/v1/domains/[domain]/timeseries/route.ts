import type { NextRequest } from 'next/server'
import { api, dataResponse } from '@/lib/api-v1'
import { timeseriesDataset, pathDomain } from '@/lib/exports'

export const dynamic = 'force-dynamic'

// GET /api/v1/domains/{domain}/timeseries?days=7[&format=csv]. Scope: domains:read.
export const GET = (req: NextRequest, ctx: { params: Promise<{ domain: string }> }) =>
  api(req, 'domains:read', async ({ auth, days }) => {
    const domain = pathDomain((await ctx.params).domain)
    return dataResponse(req, await timeseriesDataset(auth.domains, domain, days), `dmarcscope-${domain}-timeseries`)
  })
