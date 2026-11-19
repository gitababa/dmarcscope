// The HTTP side of SCIM: bearer token, body size, JSON in and out, errors in
// the SCIM error format. Cookies are never read.

import type { NextRequest } from 'next/server'
import { authenticateToken } from './api-tokens'
import { clientIp } from './client-ip'
import { appUrl } from './config'
import { getPool } from './db'
import { ERROR_SCHEMA, MAX_BODY_BYTES, ScimError } from './scim'

const TYPE = 'application/scim+json; charset=utf-8'
const HEADERS = { 'content-type': TYPE, 'cache-control': 'no-store', 'x-content-type-options': 'nosniff' }

export function scimJson(body: unknown, status = 200, extra: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), { status, headers: { ...HEADERS, ...extra } })
}

export function scimErrorResponse(e: ScimError): Response {
  return scimJson({ schemas: [ERROR_SCHEMA], status: String(e.status), ...(e.scimType ? { scimType: e.scimType } : {}), detail: e.detail }, e.status, e.status === 401 ? { 'www-authenticate': 'Bearer' } : {})
}

type Ctx = { db: ReturnType<typeof getPool>; actor: { userId: null; email: string; ip: string | null }; base: string }

// Runs a handler for an authenticated request. `readBody` parses the JSON body
// (capped) for the methods that carry one.
export async function scim(req: NextRequest, run: (ctx: Ctx, body: () => Promise<unknown>) => Promise<Response>): Promise<Response> {
  try {
    const db = getPool()
    const auth = await authenticateToken(db, req.headers.get('authorization'), 'scim')
    if (!auth) throw new ScimError(401, 'A valid SCIM token is required.')
    const ctx: Ctx = { db, actor: { userId: null, email: `scim:${auth.name}`, ip: clientIp(req.headers) }, base: appUrl().replace(/\/+$/, '') }
    const body = async () => {
      const declared = Number(req.headers.get('content-length') ?? '0')
      if (declared > MAX_BODY_BYTES) throw new ScimError(413, 'The body is too large.', 'tooMany')
      const text = await req.text()
      if (text.length > MAX_BODY_BYTES) throw new ScimError(413, 'The body is too large.', 'tooMany')
      try {
        return JSON.parse(text)
      } catch {
        throw new ScimError(400, 'The body is not valid JSON.', 'invalidSyntax')
      }
    }
    return await run(ctx, body)
  } catch (err) {
    if (err instanceof ScimError) return scimErrorResponse(err)
    console.error('[scim] request failed:', err instanceof Error ? err.message : String(err))
    return scimErrorResponse(new ScimError(500, 'Something went wrong.'))
  }
}
