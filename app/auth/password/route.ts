// Local sign-in, step 1: email and password. On success the browser gets a
// five-minute "password accepted" cookie and is asked for the second factor;
// no session yet.

import type { NextRequest } from 'next/server'
import { authProvider, hasSignInPage } from '@/lib/auth'
import { checkPassword } from '@/lib/auth/local'
import { MFA_TTL_SECONDS, sealMfaState } from '@/lib/auth/mfa-state'
import { cookieOptions, purposeCookieName, safeReturnTo } from '@/lib/auth/session'
import { clientIp } from '@/lib/client-ip'
import { getPool } from '@/lib/db'
import { formFields, forbiddenOrigin, isSameOrigin, seeOther } from '@/lib/http'

export const dynamic = 'force-dynamic'

export async function POST(req: NextRequest) {
  if (!isSameOrigin(req)) return forbiddenOrigin()
  if (!hasSignInPage(authProvider())) return seeOther('/')

  const fields = await formFields(req, ['email', 'password', 'returnTo'], 1024)
  const returnTo = safeReturnTo(fields?.returnTo)
  const again = (error: string) => seeOther(`/login?method=password&error=${error}${returnTo === '/' ? '' : `&returnTo=${encodeURIComponent(returnTo)}`}`)
  if (!fields) return again('credentials')

  const outcome = await checkPassword(getPool(), fields.email, fields.password, clientIp(req.headers))
  if (!outcome.ok) return again(outcome.reason === 'locked' ? 'locked' : 'credentials')

  const res = seeOther(`/login?method=password&step=code`)
  res.cookies.set(purposeCookieName('mfa'), await sealMfaState({ userId: outcome.userId, returnTo }), cookieOptions(MFA_TTL_SECONDS))
  return res
}
