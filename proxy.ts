// Next.js proxy (formerly "middleware"): runs in front of every route.
//
// 1. Authentication gate — everything except the explicitly public paths
//    below requires an authorized session from the configured AUTH_PROVIDER.
//    Pages and actions check again themselves (lib/auth/server.ts).
// 2. A per-request Content-Security-Policy with a script nonce.

import { NextResponse, type NextRequest } from 'next/server'
import { ConfigError, envBool } from '@/lib/config'
import { authProvider, authenticate } from '@/lib/auth'

// Reachable without a session:
//   /login, /denied, /auth/*   sign-in flow and its error pages
//   /api/healthz, /api/readyz  orchestrator probes (no data)
//   /api/cron/*                machine endpoints; each verifies the
//                              CRON_SECRET bearer token itself
function isPublicPath(path: string): boolean {
  return (
    path === '/login' ||
    path === '/denied' ||
    path.startsWith('/auth/') ||
    path === '/api/healthz' ||
    path === '/api/readyz' ||
    path.startsWith('/api/cron/')
  )
}

function buildCsp(nonce: string): string {
  const dev = process.env.NODE_ENV !== 'production'
  const directives = [
    `default-src 'self'`,
    `script-src 'self' 'nonce-${nonce}' 'strict-dynamic'${dev ? ` 'unsafe-eval'` : ''}`,
    // React inline style attributes cannot carry a nonce.
    `style-src 'self' 'unsafe-inline'`,
    `img-src 'self' data:`,
    `font-src 'self'`,
    `connect-src 'self'`,
    `object-src 'none'`,
    `base-uri 'self'`,
    `frame-ancestors 'none'`,
  ]
  // Sign-out may redirect to the identity provider's end-session endpoint,
  // which a strict form-action would block.
  if (!envBool(process.env.OIDC_LOGOUT_AT_IDP)) directives.push(`form-action 'self'`)
  return directives.join('; ')
}

export async function proxy(req: NextRequest) {
  const path = req.nextUrl.pathname

  if (!isPublicPath(path)) {
    let result
    try {
      result = await authenticate({ headers: req.headers, cookie: (name) => req.cookies.get(name)?.value })
    } catch (err) {
      if (err instanceof ConfigError) {
        console.error(`[config] ${err.message}`)
        return new NextResponse(`Server configuration error: ${err.message}\n`, {
          status: 500,
          headers: { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store' },
        })
      }
      throw err
    }

    if (result.status !== 'ok') {
      if (path.startsWith('/api/')) {
        const status = result.status === 'forbidden' ? 403 : 401
        return NextResponse.json({ ok: false, error: result.status }, { status, headers: { 'cache-control': 'no-store' } })
      }
      const url = req.nextUrl.clone()
      url.search = ''
      if (result.status === 'unauthenticated' && authProvider() === 'oidc') {
        url.pathname = '/login'
        const returnTo = path + req.nextUrl.search
        if (returnTo !== '/') url.searchParams.set('returnTo', returnTo)
      } else {
        url.pathname = '/denied'
      }
      return NextResponse.redirect(url)
    }
  }

  const nonce = btoa(crypto.randomUUID())
  const csp = buildCsp(nonce)
  const requestHeaders = new Headers(req.headers)
  requestHeaders.set('x-nonce', nonce)
  // Next.js reads the nonce from this request header and applies it to the
  // scripts it injects.
  requestHeaders.set('content-security-policy', csp)

  const res = NextResponse.next({ request: { headers: requestHeaders } })
  res.headers.set('content-security-policy', csp)
  return res
}

export const config = {
  matcher: [
    // Everything except Next's static assets and the icon.
    '/((?!_next/static|_next/image|favicon.ico|icon.svg).*)',
  ],
}
