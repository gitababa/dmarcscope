// Shared plumbing of /api/v1: bearer token in, scoped data out, errors as JSON
// with a stable code. Cookies are never read here, there is no CORS, and a
// token in a URL is not looked at.

import type { NextRequest } from 'next/server'
import { type ApiScope, type TokenAuth, authenticateToken } from './api-tokens'
import { getPool } from './db'
import { type Dataset, csvResponse, parseDays, toCsv } from './exports'

const HEADERS = { 'cache-control': 'no-store', 'x-content-type-options': 'nosniff' }

export function jsonError(status: number, code: string, message: string, extra: Record<string, string> = {}): Response {
  return Response.json({ error: { code, message } }, { status, headers: { ...HEADERS, ...extra } })
}

export const unauthorized = () => jsonError(401, 'unauthorized', 'A valid token is required.', { 'www-authenticate': 'Bearer' })

type Ctx = { auth: TokenAuth; req: NextRequest; days: number }

// Authenticates, checks the scope the endpoint needs, validates ?days=, runs.
export async function api(req: NextRequest, needed: ApiScope, run: (c: Ctx) => Promise<Response>): Promise<Response> {
  let auth: TokenAuth | null
  try {
    auth = await authenticateToken(getPool(), req.headers.get('authorization'), 'api')
  } catch (err) {
    console.error('[api] token check failed:', err instanceof Error ? err.message : String(err))
    return jsonError(503, 'unavailable', 'Temporarily unavailable.')
  }
  if (!auth) return unauthorized()
  if (!auth.scopes.includes(needed)) return jsonError(403, 'insufficient_scope', `This token lacks the ${needed} scope.`)
  const days = parseDays(req.nextUrl.searchParams.get('days'))
  if (days == null) return jsonError(400, 'invalid_days', 'days must be a whole number from 1 to 90.')
  try {
    return await run({ auth, req, days })
  } catch (err) {
    console.error('[api] request failed:', err instanceof Error ? err.message : String(err))
    return jsonError(500, 'internal', 'Something went wrong.')
  }
}

// JSON by default, CSV with ?format=csv.
export function dataResponse(req: NextRequest, d: Dataset | null, csvName: string): Response {
  if (!d) return jsonError(404, 'not_found', 'No such domain.')
  const format = req.nextUrl.searchParams.get('format')
  if (format === 'csv') return csvResponse(toCsv(d), csvName)
  if (format != null && format !== 'json') return jsonError(400, 'invalid_format', 'format must be json or csv.')
  return Response.json({ data: d.rows }, { headers: HEADERS })
}
