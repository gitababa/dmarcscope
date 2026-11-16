// Next.js proxy (formerly "middleware"): runs in front of every route.
//
// 1. Authentication gate — everything except the explicitly public paths
//    below requires an authorized session from the configured AUTH_PROVIDER.
//    Roles come from the database on every request: one indexed users query,
//    plus the cached settings snapshot (lib/settings/store.ts).
//    Pages and actions check again themselves (lib/auth/server.ts).
//    With AUTH_PROVIDER unset and no owner yet, only /setup is served.
// 2. A per-request Content-Security-Policy with a script nonce.

import { NextResponse, type NextRequest } from 'next/server'
import { ConfigError, appUrl, envBool } from '@/lib/config'
import { authProvider, authenticate, hasSignInPage } from '@/lib/auth'

// Reachable without a session:
//   /login, /denied, /auth/*   sign-in flow and its error pages
//   /setup, /setup/*           first-run wizard (404 once an owner exists;
//                              unlocked only by the setup token)
//   /api/healthz, /api/readyz  orchestrator probes (no data)
//   /api/cron/*                machine endpoints; each verifies the
//                              CRON_SECRET bearer token itself
function isPublicPath(path: string): boolean {
  return (
    path === '/login' ||
    path === '/denied' ||
    path.startsWith('/auth/') ||
    path === '/setup' ||
    path.startsWith('/setup/') ||
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
    const noStore = { 'cache-control': 'no-store' }
    try {
      const result = await authenticate({ headers: req.headers, cookie: (name) => req.cookies.get(name)?.value })

      if (result.status !== 'ok') {
        if (path.startsWith('/api/')) {
          const status = result.status === 'forbidden' ? 403 : result.status === 'setup_required' ? 503 : 401
          return NextResponse.json({ ok: false, error: result.status }, { status, headers: noStore })
        }
        // Redirect to the configured public URL: behind a reverse proxy the
        // request URL can carry the container's own host and port.
        const url = new URL('/denied', process.env.APP_URL?.trim() ? appUrl() : req.nextUrl.origin)
        if (result.status === 'setup_required') {
          url.pathname = '/setup'
        } else if (result.status === 'unauthenticated' && hasSignInPage(authProvider())) {
          url.pathname = '/login'
          const returnTo = path + req.nextUrl.search
          if (returnTo !== '/') url.searchParams.set('returnTo', returnTo)
        }
        return NextResponse.redirect(url)
      }
    } catch (err) {
      if (!(err instanceof ConfigError)) {
        // Most likely the database (roles live there now). Fail closed, and
        // tell a probe or a person to come back rather than showing a crash.
        console.error('[auth] request gate could not decide:', err instanceof Error ? err.message : String(err))
        if (path.startsWith('/api/')) {
          return NextResponse.json({ ok: false, error: 'unavailable' }, { status: 503, headers: noStore })
        }
        return new NextResponse('Temporarily unavailable. Please try again in a moment.\n', {
          status: 503,
          headers: { 'content-type': 'text/plain; charset=utf-8', 'retry-after': '5', ...noStore },
        })
      }
      // The detail is for the operator (server log). Whoever is asking is not
      // signed in, so in production they are only told that it is broken.
      console.error(`[config] ${err.message}`)
      const message =
        process.env.NODE_ENV === 'production'
          ? 'Server configuration error. The details are in the server log.'
          : `Server configuration error: ${err.message}`
      if (path.startsWith('/api/')) {
        return NextResponse.json({ ok: false, error: 'server_configuration' }, { status: 500, headers: noStore })
      }
      return new NextResponse(`${message}\n`, {
        status: 500,
        headers: { 'content-type': 'text/plain; charset=utf-8', ...noStore },
      })
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
