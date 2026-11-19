import type { NextRequest } from 'next/server'
import { deleteGroup, getGroup, patchGroup, replaceGroup } from '@/lib/scim'
import { scim, scimJson } from '@/lib/scim-http'

export const dynamic = 'force-dynamic'

type P = { params: Promise<{ id: string }> }

export const GET = (req: NextRequest, p: P) => scim(req, async (ctx) => scimJson(await getGroup(ctx, (await p.params).id)))
export const PUT = (req: NextRequest, p: P) => scim(req, async (ctx, body) => scimJson(await replaceGroup(ctx, (await p.params).id, await body())))
export const PATCH = (req: NextRequest, p: P) => scim(req, async (ctx, body) => scimJson(await patchGroup(ctx, (await p.params).id, await body())))
export const DELETE = (req: NextRequest, p: P) =>
  scim(req, async (ctx) => {
    await deleteGroup(ctx, (await p.params).id)
    return new Response(null, { status: 204, headers: { 'cache-control': 'no-store' } })
  })
