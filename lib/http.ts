// Helpers for the route handlers that take form posts before anyone is signed
// in (/auth/password, /auth/second-factor, /setup/*). Server actions get
// Next.js's own cross-origin check; these are plain routes, so they do it
// themselves.

import { NextResponse, type NextRequest } from 'next/server'
import { appUrl } from './config'

// A form post must come from a page of this deployment. Browsers send
// Origin with every POST; Sec-Fetch-Site covers the rare one that does not.
export function isSameOrigin(req: NextRequest): boolean {
  let expected: string
  try {
    expected = appUrl()
  } catch {
    return false
  }
  const origin = req.headers.get('origin')
  if (origin) return origin === expected
  return req.headers.get('sec-fetch-site') === 'same-origin'
}

// Redirect (303, so the browser follows with a GET) to a path on the public
// URL, never to the Host header the request arrived with.
export function seeOther(path: string): NextResponse {
  const res = NextResponse.redirect(new URL(path, appUrl()), 303)
  res.headers.set('cache-control', 'no-store')
  return res
}

export function notFoundResponse(): NextResponse {
  return new NextResponse('Not found\n', { status: 404, headers: { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store' } })
}

export function forbiddenOrigin(): NextResponse {
  return new NextResponse('Cross-origin form posts are refused.\n', {
    status: 403,
    headers: { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store' },
  })
}

// Form fields as strings, with a length limit so that nothing unbounded is
// hashed, stored or echoed.
export async function formFields(req: NextRequest, names: string[], maxLength = 2048): Promise<Record<string, string> | null> {
  const type = req.headers.get('content-type') || ''
  if (!type.startsWith('application/x-www-form-urlencoded') && !type.startsWith('multipart/form-data')) return null
  const length = Number(req.headers.get('content-length') || 0)
  if (length > 64 * 1024) return null
  let form: FormData
  try {
    form = await req.formData()
  } catch {
    return null
  }
  const out: Record<string, string> = {}
  for (const name of names) {
    const v = form.get(name)
    out[name] = typeof v === 'string' ? v.slice(0, maxLength) : ''
  }
  return out
}
