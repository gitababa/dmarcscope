import { NextResponse, type NextRequest } from 'next/server'
import { appUrl } from '@/lib/config'
import { authenticate } from '@/lib/auth'
import { recordAudit } from '@/lib/audit'
import { ruleGroups } from '@/lib/auth/authz'
import { currentOidcSettings } from '@/lib/auth/connection'
import { defaultDirectory } from '@/lib/auth/directory'
import { LoginError, exchangeCode, identityFromClaimsWith } from '@/lib/auth/oidc'
import { resolveAccess } from '@/lib/auth/resolve'
import { clientIp } from '@/lib/client-ip'
import { getPool } from '@/lib/db'
import { configStore, getSessionTtlSeconds } from '@/lib/settings'
import { type TestResult, getConnection, recordTest, settingsFromRow, summarizeClaims, wouldAdmit } from '@/lib/sso'
import {
  type LoginState,
  cookieOptions,
  loginCookieName,
  sealSession,
  sessionCookieName,
  unsealLoginState,
} from '@/lib/auth/session'

export const dynamic = 'force-dynamic'

// OIDC redirect URI: exchanges the code, validates the ID token, and issues
// the session cookie. A test of a draft connection (see /auth/sso-test) comes
// back here too: it records the outcome and issues nothing.
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
    const login = await unsealLoginState(req.cookies.get(loginCookieName())?.value)
    if (login?.test) return await handleTest(req, login, base, clearLoginCookie)

    const connection = await currentOidcSettings()
    if (!connection) return NextResponse.redirect(new URL('/', base))
    if (!login) return fail('expired')

    const dir = defaultDirectory()
    const claims = await exchangeCode(connection.settings, req.nextUrl, login)
    const identity = identityFromClaimsWith(connection.settings, claims, process.env, ruleGroups((await dir.config()).rules))
    // Finds or records the person (a first sign-in nobody admits becomes a
    // pending request an administrator can approve).
    const access = await resolveAccess(identity, 'oidc', {}, process.env, dir)
    const ok = access.status === 'ok'
    // The user id goes into the cookie whenever there is a row, so that a
    // pending person sees "Access not granted" rather than the sign-in page.
    const userId = ok ? access.session.userId : (await dir.findByEmail(identity.email))?.id ?? null
    await recordAudit(getPool(), {
      action: ok ? 'sign_in' : 'sign_in_denied',
      actor: { userId, email: identity.email, ip: clientIp(req.headers) },
      detail: { method: 'oidc', role: ok ? access.session.role : null },
    })
    if (ok && userId != null) {
      await getPool().query('UPDATE users SET last_login_at = NOW(), failed_logins = 0 WHERE id = $1', [userId])
    }

    // A session is issued even when the user has no role yet: /denied then
    // shows who they are signed in as, and access starts working as soon as
    // an admin admits them (roles are evaluated per request, not at sign-in).
    const ttl = await getSessionTtlSeconds()
    const res = NextResponse.redirect(new URL(ok ? login.returnTo : '/denied', base))
    res.cookies.set(
      sessionCookieName(),
      await sealSession(identity, process.env, { userId: userId ?? undefined, method: 'oidc', ttlSeconds: ttl }),
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

// The end of a test sign-in. Recorded only for the owner who started it, in
// their current session; nothing about anyone's session or user row changes.
async function handleTest(req: NextRequest, login: LoginState, base: string, clearLoginCookie: (res: NextResponse) => unknown) {
  const test = login.test!
  const db = getPool()
  const done = () => {
    const res = NextResponse.redirect(new URL('/admin/sso/test', base))
    clearLoginCookie(res)
    res.headers.set('cache-control', 'no-store')
    return res
  }

  const auth = await authenticate({ headers: req.headers, cookie: (n) => req.cookies.get(n)?.value })
  if (auth.status !== 'ok' || auth.session.role !== 'owner' || auth.session.userId !== test.userId) {
    await recordAudit(db, {
      action: 'action_refused',
      actor: { userId: auth.status === 'ok' ? auth.session.userId : null, email: null, ip: clientIp(req.headers) },
      target: `sso:${test.connectionId}`,
      detail: { action: 'sso_test', reason: 'not_the_owner_who_started_it' },
    })
    return done()
  }

  const by = { userId: auth.session.userId, email: auth.session.identity.email }
  const draft = await getConnection(db, 'draft')
  if (!draft || draft.id !== test.connectionId || draft.revision !== test.revision) {
    // The draft changed while the test ran; the outcome would describe
    // something else. recordTest ignores it as well.
    return done()
  }

  const result: TestResult = { ok: false, at: new Date().toISOString(), revision: test.revision, by }
  const settings = settingsFromRow(draft)
  try {
    const providerError = req.nextUrl.searchParams.get('error')
    if (providerError) {
      // e.g. redirect_uri_mismatch, invalid_client, access_denied
      const description = req.nextUrl.searchParams.get('error_description') ?? ''
      result.error = { code: 'provider', message: `${providerError}${description ? `: ${description}` : ''}`.slice(0, 300) }
    } else {
      const claims = await exchangeCode(settings, req.nextUrl, login)
      result.claims = summarizeClaims(claims, settings)
      const { rules } = await configStore().snapshot()
      const identity = identityFromClaimsWith(settings, claims, process.env, rules.filter((r) => r.kind === 'group').map((r) => r.value))
      result.identity = { email: identity.email, name: identity.name ?? null, groups: identity.groups }
      result.admission = await wouldAdmit(db, identity, rules)
      result.ok = true
    }
  } catch (err) {
    result.error = {
      code: err instanceof LoginError ? err.code : 'exchange',
      message: (err instanceof Error ? err.message : String(err)).replace(/\s+/g, ' ').slice(0, 300),
    }
  }
  await recordTest(db, test, result)
  return done()
}
