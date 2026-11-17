// GET /auth/sso-test: an owner tests the draft single sign-on connection with
// a real sign-in (opened in a new window from Admin → Sign-in). The flow comes
// back to /auth/callback, which recognizes the test from the login-state
// cookie, records the outcome and issues no session.

import { NextResponse, type NextRequest } from 'next/server'
import { recordAudit } from '@/lib/audit'
import { authProvider, authenticate } from '@/lib/auth'
import { beginLoginWith, discover } from '@/lib/auth/oidc'
import { clientIp } from '@/lib/client-ip'
import { LOGIN_TTL_SECONDS, cookieOptions, loginCookieName, sealLoginState } from '@/lib/auth/session'
import { appUrl } from '@/lib/config'
import { getPool } from '@/lib/db'
import { getConnection, recordTest, settingsFromRow } from '@/lib/sso'

export const dynamic = 'force-dynamic'

const RESULT = '/admin/sso/test'

export async function GET(req: NextRequest) {
  const base = appUrl()
  const auth = await authenticate({ headers: req.headers, cookie: (n) => req.cookies.get(n)?.value })
  const owner = auth.status === 'ok' && auth.session.role === 'owner' && auth.session.userId != null ? auth.session : null
  if (!owner || authProvider() !== 'local') {
    await recordAudit(getPool(), {
      action: 'action_refused',
      actor: { userId: auth.status === 'ok' ? auth.session.userId : null, email: auth.status === 'ok' ? auth.session.identity.email : null, ip: clientIp(req.headers) },
      target: 'sso',
      detail: { action: 'sso_test', reason: owner ? 'environment' : 'not_allowed' },
    })
    return new NextResponse('Not found\n', { status: 404, headers: { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store' } })
  }
  const access = { session: owner }
  const db = getPool()
  const draft = await getConnection(db, 'draft')
  if (!draft) return NextResponse.redirect(new URL('/admin/sso', base))

  const test = { connectionId: draft.id, revision: draft.revision, userId: access.session.userId! }
  const by = { userId: access.session.userId!, email: access.session.identity.email }
  try {
    const settings = settingsFromRow(draft)
    // A broken issuer fails here, before anyone is sent anywhere.
    await discover(settings)
    const { url, state } = await beginLoginWith(settings, RESULT)
    const res = NextResponse.redirect(url)
    res.cookies.set(loginCookieName(), await sealLoginState({ ...state, test }), cookieOptions(LOGIN_TTL_SECONDS))
    res.headers.set('cache-control', 'no-store')
    return res
  } catch (err) {
    await recordTest(db, test, {
      ok: false,
      at: new Date().toISOString(),
      revision: draft.revision,
      by,
      error: { code: 'discovery', message: describe(err) },
    })
    return NextResponse.redirect(new URL(RESULT, base))
  }
}

// An error for the owner's eyes: the library's message, shortened. It never
// includes the client secret (openid-client does not put it in messages).
function describe(err: unknown): string {
  const msg = err instanceof Error ? err.message : String(err)
  return msg.replace(/\s+/g, ' ').slice(0, 300)
}
