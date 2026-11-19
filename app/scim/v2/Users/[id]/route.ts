import type { NextRequest } from 'next/server'
import { deleteUser, getUser, patchUser, replaceUser } from '@/lib/scim'
import { scim, scimJson } from '@/lib/scim-http'

export const dynamic = 'force-dynamic'

type P = { params: Promise<{ id: string }> }

export const GET = (req: NextRequest, p: P) => scim(req, async (ctx) => scimJson(await getUser(ctx, (await p.params).id)))
export const PUT = (req: NextRequest, p: P) => scim(req, async (ctx, body) => scimJson(await replaceUser(ctx, (await p.params).id, await body())))
export const PATCH = (req: NextRequest, p: P) => scim(req, async (ctx, body) => scimJson(await patchUser(ctx, (await p.params).id, await body())))
export const DELETE = (req: NextRequest, p: P) =>
  scim(req, async (ctx) => {
    await deleteUser(ctx, (await p.params).id)
    return new Response(null, { status: 204, headers: { 'cache-control': 'no-store' } })
  })
