import type { NextRequest } from 'next/server'
import { createGroup, listGroups } from '@/lib/scim'
import { scim, scimJson } from '@/lib/scim-http'

export const dynamic = 'force-dynamic'

export const GET = (req: NextRequest) => scim(req, async (ctx) => scimJson(await listGroups(ctx, req.nextUrl.searchParams)))

export const POST = (req: NextRequest) =>
  scim(req, async (ctx, body) => {
    const group = await createGroup(ctx, await body())
    return scimJson(group, 201, { location: group.meta.location })
  })
