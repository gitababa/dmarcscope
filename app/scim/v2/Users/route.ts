import type { NextRequest } from 'next/server'
import { createUser, listUsers } from '@/lib/scim'
import { scim, scimJson } from '@/lib/scim-http'

export const dynamic = 'force-dynamic'

export const GET = (req: NextRequest) => scim(req, async (ctx) => scimJson(await listUsers(ctx, req.nextUrl.searchParams)))

export const POST = (req: NextRequest) =>
  scim(req, async (ctx, body) => {
    const user = await createUser(ctx, await body())
    return scimJson(user, 201, { location: user.meta.location })
  })
