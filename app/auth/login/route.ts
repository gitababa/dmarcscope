import { NextResponse, type NextRequest } from 'next/server'
import { ConfigError, appUrl } from '@/lib/config'
import { authProvider } from '@/lib/auth'
import { beginLogin } from '@/lib/auth/oidc'
import { LOGIN_TTL_SECONDS, cookieOptions, loginCookieName, safeReturnTo, sealLoginState } from '@/lib/auth/session'

export const dynamic = 'force-dynamic'

// Starts the OIDC authorization-code flow: stores state / nonce / PKCE
// verifier in a short-lived encrypted cookie and redirects to the provider.
export async function GET(req: NextRequest) {
  try {
    if (authProvider() !== 'oidc') return NextResponse.redirect(new URL('/', appUrl()))
    const returnTo = safeReturnTo(req.nextUrl.searchParams.get('returnTo'))
    const { url, state } = await beginLogin(returnTo)
    const res = NextResponse.redirect(url)
    res.cookies.set(loginCookieName(), await sealLoginState(state), cookieOptions(LOGIN_TTL_SECONDS))
    res.headers.set('cache-control', 'no-store')
    return res
  } catch (err) {
    console.error('[auth] could not start sign-in:', err instanceof Error ? err.message : err)
    const code = err instanceof ConfigError ? 'config' : 'provider'
    return NextResponse.redirect(new URL(`/login?error=${code}`, req.nextUrl.origin))
  }
}
