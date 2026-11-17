// POST /auth/sso-test: an owner tests the draft single sign-on connection with
// a real sign-in (opened in a new window from Admin → Sign-in). The flow comes
// back to /auth/callback, which recognizes the test from the login-state
// cookie, records the outcome and issues no session.

import { NextResponse, type NextRequest } from 'next/server'
import { recordAudit } from '@/lib/audit'
import { authProvider, authenticate } from '@/lib/auth'
import { beginLoginWith, discover } from '@/lib/auth/oidc'
import { clientIp } from '@/lib/client-ip'
import { forbiddenOrigin, isSameOrigin } from '@/lib/http'
import { LOGIN_TTL_SECONDS, cookieOptions, loginCookieName, sealLoginState } from '@/lib/auth/session'
import { appUrl } from '@/lib/config'
import { getPool } from '@/lib/db'
import { getConnection, recordTest, settingsFromRow } from '@/lib/sso'

export const dynamic = 'force-dynamic'

const RESULT = '/admin/sso/test'

// A form post from the Sign-in page (not a link), so that another site cannot
// make the owner's browser start a test.
export async function POST(req: NextRequest) {
  if (!isSameOrigin(req)) return forbiddenOrigin()
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
  if (!draft) return NextResponse.redirect(new URL('/admin/sso', base), 303)

  const test = { connectionId: draft.id, revision: draft.revision, userId: access.session.userId! }
  const by = { userId: access.session.userId!, email: access.session.identity.email }
  try {
    const settings = settingsFromRow(draft)
    // A broken issuer fails here, before anyone is sent anywhere.
    await discover(settings)
    const { url, state } = await beginLoginWith(settings, RESULT)
    // Not a redirect: after a form post, browsers apply the page's
    // form-action 'self' policy to redirects too, which would block the
    // provider. A same-origin page that moves on by itself is not affected.
    const res = continuePage(url)
    res.cookies.set(loginCookieName(), await sealLoginState({ ...state, test }), cookieOptions(LOGIN_TTL_SECONDS))
    return res
  } catch (err) {
    await recordTest(db, test, {
      ok: false,
      at: new Date().toISOString(),
      revision: draft.revision,
      by,
      error: { code: 'discovery', message: describe(err) },
    })
    return NextResponse.redirect(new URL(RESULT, base), 303)
  }
}

function continuePage(url: string): NextResponse {
  const href = url.replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;')
  const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta http-equiv="refresh" content="0;url=${href}"><title>Test sign-in</title></head><body style="font-family:system-ui,sans-serif;padding:2rem"><p>Continuing to your sign-in provider&hellip;</p><p><a href="${href}">Continue</a></p></body></html>`
  return new NextResponse(html, { status: 200, headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' } })
}

// An error for the owner's eyes: the library's message, shortened. It never
// includes the client secret (openid-client does not put it in messages).
function describe(err: unknown): string {
  const msg = err instanceof Error ? err.message : String(err)
  return msg.replace(/\s+/g, ' ').slice(0, 300)
}
