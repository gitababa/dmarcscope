import type { NextRequest } from 'next/server'
import { api, dataResponse } from '@/lib/api-v1'
import { problemsDataset } from '@/lib/exports'

export const dynamic = 'force-dynamic'

// GET /api/v1/problems?days=7[&domain=example.com][&format=csv]: sources whose
// mail fails DMARC, for the domains the token may see. Scope: reports:read.
export const GET = (req: NextRequest) =>
  api(req, 'reports:read', async ({ auth, days }) => {
    const domain = req.nextUrl.searchParams.get('domain')?.toLowerCase() || undefined
    return dataResponse(req, await problemsDataset(auth.domains, days, domain), 'dmarcscope-problems')
  })
