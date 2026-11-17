import { NextResponse, type NextRequest } from 'next/server'
import { appUrl } from '@/lib/config'
import { authProvider } from '@/lib/auth'
import { recordAudit } from '@/lib/audit'
import { ruleGroups } from '@/lib/auth/authz'
import { defaultDirectory } from '@/lib/auth/directory'
import { resolveAccess } from '@/lib/auth/resolve'
import { clientIp } from '@/lib/client-ip'
import { getPool } from '@/lib/db'
import { getSessionTtlSeconds } from '@/lib/settings'
import { LoginError, completeLogin } from '@/lib/auth/oidc'
import {
  cookieOptions,
  loginCookieName,
  sealSession,
  sessionCookieName,
  unsealLoginState,
} from '@/lib/auth/session'

export const dynamic = 'force-dynamic'

// OIDC redirect URI: exchanges the code, validates the ID token, and issues
// the session cookie.
export async function GET(req: NextRequest) {
  const base = appUrl()
  // Expire the login-state cookie with the same attributes it was set with:
  // a bare delete drops Secure, and browsers ignore that for a __Host- cookie.
  const clearLoginCookie = (res: NextResponse) => res.cookies.set(loginCookieName(), '', cookieOptions(0))
  const fail = (code: string) => {
    const res = NextResponse.redirect(new URL(`/login?error=${code}`, base))
    clearLoginCookie(res)
    res.headers.set('cache-control', 'no-store')
    return res
  }

  try {
    if (authProvider() !== 'oidc') return NextResponse.redirect(new URL('/', base))

    const login = await unsealLoginState(req.cookies.get(loginCookieName())?.value)
    if (!login) return fail('expired')

    const dir = defaultDirectory()
    const identity = await completeLogin(req.nextUrl, login, process.env, ruleGroups((await dir.config()).rules))
    // Finds or records the person (a first sign-in nobody admits becomes a
    // pending request an administrator can approve).
    const access = await resolveAccess(identity, 'oidc', {}, process.env, dir)
    const ok = access.status === 'ok'
    await recordAudit(getPool(), {
      action: ok ? 'sign_in' : 'sign_in_denied',
      actor: { userId: ok ? access.session.userId : null, email: identity.email, ip: clientIp(req.headers) },
      detail: { method: 'oidc', role: ok ? access.session.role : null },
    })
    if (ok && access.session.userId != null) {
      await getPool().query('UPDATE users SET last_login_at = NOW(), failed_logins = 0 WHERE id = $1', [access.session.userId])
    }

    // A session is issued even when the user has no role yet: /denied then
    // shows who they are signed in as, and access starts working as soon as
    // an admin admits them (roles are evaluated per request, not at sign-in).
    const ttl = await getSessionTtlSeconds()
    const res = NextResponse.redirect(new URL(ok ? login.returnTo : '/denied', base))
    res.cookies.set(
      sessionCookieName(),
      await sealSession(identity, process.env, { userId: ok ? (access.session.userId ?? undefined) : undefined, method: 'oidc', ttlSeconds: ttl }),
      cookieOptions(ttl)
    )
    clearLoginCookie(res)
    res.headers.set('cache-control', 'no-store')
    return res
  } catch (err) {
    console.error('[auth] sign-in failed:', err instanceof Error ? err.message : err)
    return fail(err instanceof LoginError ? err.code : 'failed')
  }
}
