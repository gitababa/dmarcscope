import { NextResponse, type NextRequest } from 'next/server'
import { appUrl } from '@/lib/config'
import { authProvider } from '@/lib/auth'
import { resolveRole } from '@/lib/auth/authz'
import { LoginError, completeLogin } from '@/lib/auth/oidc'
import { audit } from '@/lib/auth/server'
import {
  cookieOptions,
  loginCookieName,
  sealSession,
  sessionCookieName,
  sessionTtlSeconds,
  unsealLoginState,
} from '@/lib/auth/session'

export const dynamic = 'force-dynamic'

// OIDC redirect URI: exchanges the code, validates the ID token, and issues
// the session cookie.
export async function GET(req: NextRequest) {
  const base = appUrl()
  const fail = (code: string) => {
    const res = NextResponse.redirect(new URL(`/login?error=${code}`, base))
    res.cookies.delete(loginCookieName())
    res.headers.set('cache-control', 'no-store')
    return res
  }

  try {
    if (authProvider() !== 'oidc') return NextResponse.redirect(new URL('/', base))

    const login = await unsealLoginState(req.cookies.get(loginCookieName())?.value)
    if (!login) return fail('expired')

    const identity = await completeLogin(req.nextUrl, login)
    const role = resolveRole(identity)
    audit(role ? 'sign_in' : 'sign_in_denied', { email: identity.email, role })

    // A session is issued even when the user has no role yet: /denied then
    // shows who they are signed in as, and access starts working as soon as
    // an admin adds them (roles are evaluated per request, not at sign-in).
    const res = NextResponse.redirect(new URL(role ? login.returnTo : '/denied', base))
    res.cookies.set(sessionCookieName(), await sealSession(identity), cookieOptions(sessionTtlSeconds()))
    res.cookies.delete(loginCookieName())
    res.headers.set('cache-control', 'no-store')
    return res
  } catch (err) {
    console.error('[auth] sign-in failed:', err instanceof Error ? err.message : err)
    return fail(err instanceof LoginError ? err.code : 'failed')
  }
}
