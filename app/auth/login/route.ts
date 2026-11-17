import { NextResponse, type NextRequest } from 'next/server'
import { ConfigError, appUrl } from '@/lib/config'
import { currentOidcSettings } from '@/lib/auth/connection'
import { beginLoginWith } from '@/lib/auth/oidc'
import { LOGIN_TTL_SECONDS, cookieOptions, loginCookieName, safeReturnTo, sealLoginState } from '@/lib/auth/session'

export const dynamic = 'force-dynamic'

// Starts the OIDC authorization-code flow with the current connection (the
// environment's, or the one activated in the panel): stores state / nonce /
// PKCE verifier in a short-lived encrypted cookie and redirects to the
// provider.
export async function GET(req: NextRequest) {
  try {
    const connection = await currentOidcSettings()
    if (!connection) return NextResponse.redirect(new URL('/login', appUrl()))
    const returnTo = safeReturnTo(req.nextUrl.searchParams.get('returnTo'))
    const { url, state } = await beginLoginWith(connection.settings, returnTo)
    const res = NextResponse.redirect(url)
    res.cookies.set(loginCookieName(), await sealLoginState(state), cookieOptions(LOGIN_TTL_SECONDS))
    res.headers.set('cache-control', 'no-store')
    return res
  } catch (err) {
    console.error('[auth] could not start sign-in:', err instanceof Error ? err.message : err)
    const code = err instanceof ConfigError ? 'config' : 'provider'
    let base: string
    try {
      base = appUrl()
    } catch {
      base = req.nextUrl.origin
    }
    return NextResponse.redirect(new URL(`/login?error=${code}`, base))
  }
}
