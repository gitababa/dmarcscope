import type { NextRequest } from 'next/server'
import { api, dataResponse } from '@/lib/api-v1'
import { domainsDataset } from '@/lib/exports'

export const dynamic = 'force-dynamic'

// GET /api/v1/domains?days=7[&format=csv]: the domains the token may see, with
// their volumes. Scope: domains:read.
export const GET = (req: NextRequest) => api(req, 'domains:read', async ({ auth, days }) => dataResponse(req, await domainsDataset(auth.domains, days), 'dmarcscope-domains'))
